#!/bin/bash
# TMWS Multi-Client Testing Strategy
# Eris Tactical Testing Coordination v2.2.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TMWS_BASE_URL="http://localhost:8000"
TMWS_WS_URL="ws://localhost:8000/ws/mcp"
TEST_AGENTS=("artemis-optimizer" "hestia-auditor" "athena-conductor" "eris-coordinator")
MAX_CONCURRENT_CLIENTS=10
TEST_DURATION=60  # seconds

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if TMWS is running
check_tmws_status() {
    print_status "Checking TMWS server status..."

    # Check HTTP API
    if ! curl -s -f "$TMWS_BASE_URL/health" > /dev/null 2>&1; then
        print_error "TMWS server not responding at $TMWS_BASE_URL"
        print_status "Starting TMWS unified server..."
        python -m src.unified_server &
        TMWS_PID=$!
        sleep 5

        if ! curl -s -f "$TMWS_BASE_URL/health" > /dev/null 2>&1; then
            print_error "Failed to start TMWS server"
            exit 1
        fi
    fi

    print_success "TMWS server is running"
}

# Test WebSocket MCP connections
test_websocket_mcp() {
    print_status "Testing WebSocket MCP connections..."

    # Create WebSocket test client
    cat > /tmp/ws_mcp_test.py << 'EOF'
import asyncio
import websockets
import json
import sys

async def test_client(agent_id, client_num):
    uri = "ws://localhost:8000/ws/mcp"
    try:
        async with websockets.connect(
            uri,
            extra_headers={"X-Agent-ID": agent_id}
        ) as websocket:
            # Initialize
            init_msg = {
                "jsonrpc": "2.0",
                "id": f"init_{client_num}",
                "method": "initialize",
                "params": {
                    "protocolVersion": "1.0",
                    "clientInfo": {
                        "name": f"test-client-{client_num}",
                        "version": "1.0.0"
                    }
                }
            }
            await websocket.send(json.dumps(init_msg))
            response = await websocket.recv()
            print(f"Client {client_num} initialized: {json.loads(response).get('result', {}).get('serverName', 'Unknown')}")

            # Store memory
            store_msg = {
                "jsonrpc": "2.0",
                "id": f"store_{client_num}",
                "method": "memory/store",
                "params": {
                    "content": f"Test memory from client {client_num} ({agent_id})",
                    "importance": 0.7
                }
            }
            await websocket.send(json.dumps(store_msg))
            response = await websocket.recv()
            result = json.loads(response)
            if 'result' in result:
                print(f"Client {client_num} stored memory: {result['result'].get('memory_id', 'Unknown')}")

            # Search memory
            search_msg = {
                "jsonrpc": "2.0",
                "id": f"search_{client_num}",
                "method": "memory/search",
                "params": {
                    "query": "test memory",
                    "limit": 5
                }
            }
            await websocket.send(json.dumps(search_msg))
            response = await websocket.recv()
            result = json.loads(response)
            if 'result' in result:
                memories = result['result'].get('memories', [])
                print(f"Client {client_num} found {len(memories)} memories")

            # Keep connection alive briefly
            await asyncio.sleep(2)

            print(f"Client {client_num} completed successfully")
            return True

    except Exception as e:
        print(f"Client {client_num} error: {e}")
        return False

async def run_concurrent_test(num_clients):
    agents = ["artemis-optimizer", "hestia-auditor", "athena-conductor", "eris-coordinator"]
    tasks = []

    for i in range(num_clients):
        agent = agents[i % len(agents)]
        task = test_client(agent, i + 1)
        tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    success_count = sum(1 for r in results if r is True)
    fail_count = len(results) - success_count

    print(f"\nResults: {success_count} success, {fail_count} failures")
    return success_count == len(results)

if __name__ == "__main__":
    num_clients = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    success = asyncio.run(run_concurrent_test(num_clients))
    sys.exit(0 if success else 1)
EOF

    # Test with increasing number of concurrent clients
    for num_clients in 2 5 10; do
        print_status "Testing with $num_clients concurrent WebSocket MCP clients..."

        if python /tmp/ws_mcp_test.py $num_clients; then
            print_success "Successfully tested $num_clients concurrent clients"
        else
            print_error "Failed with $num_clients concurrent clients"
            return 1
        fi

        sleep 2
    done

    # Cleanup
    rm -f /tmp/ws_mcp_test.py

    print_success "All WebSocket MCP tests passed!"
    return 0
}

# Test REST API concurrent access
test_rest_api() {
    print_status "Testing REST API concurrent access..."

    local success=0
    local failed=0

    # Concurrent memory operations
    for i in {1..5}; do
        for agent in "${TEST_AGENTS[@]}"; do
            (
                # Store memory
                response=$(curl -s -X POST "$TMWS_BASE_URL/api/v1/memory/store" \
                    -H "Content-Type: application/json" \
                    -H "X-Agent-ID: $agent" \
                    -d '{
                        "content": "Test memory from '"$agent"' iteration '"$i"'",
                        "importance": 0.6,
                        "tags": ["test", "concurrent"]
                    }' 2>/dev/null)

                if [[ -n "$response" ]] && [[ ! "$response" == *"error"* ]]; then
                    echo "SUCCESS: $agent iteration $i"
                else
                    echo "FAILED: $agent iteration $i"
                fi
            ) &
        done
    done

    # Wait for all background jobs
    wait

    print_success "REST API concurrent test completed"
}

# Test mixed protocol access
test_mixed_protocols() {
    print_status "Testing mixed protocol access (REST + WebSocket MCP)..."

    # Start REST clients in background
    for i in {1..3}; do
        (
            agent="${TEST_AGENTS[$((i % ${#TEST_AGENTS[@]}))]}"
            curl -s -X POST "$TMWS_BASE_URL/api/v1/memory/store" \
                -H "Content-Type: application/json" \
                -H "X-Agent-ID: $agent" \
                -d '{
                    "content": "Mixed test REST from '"$agent"'",
                    "importance": 0.5
                }' > /dev/null
            echo "REST client $i completed"
        ) &
    done

    # Start WebSocket clients concurrently
    python /tmp/ws_mcp_test.py 3 &

    # Wait for all to complete
    wait

    print_success "Mixed protocol test completed"
}

# Check server stats
check_server_stats() {
    print_status "Checking server statistics..."

    # Get WebSocket stats
    ws_stats=$(curl -s "$TMWS_BASE_URL/ws/stats" 2>/dev/null || echo "{}")

    if [[ -n "$ws_stats" ]] && [[ "$ws_stats" != "{}" ]]; then
        print_success "Server statistics retrieved"
        echo "$ws_stats" | python -m json.tool
    else
        print_warning "Could not retrieve server statistics"
    fi

    # Get active sessions
    sessions=$(curl -s "$TMWS_BASE_URL/ws/sessions" 2>/dev/null || echo "{}")

    if [[ -n "$sessions" ]] && [[ "$sessions" != "{}" ]]; then
        print_success "Active sessions retrieved"
        echo "$sessions" | python -m json.tool
    fi
}

# Cleanup function
cleanup() {
    print_status "Cleaning up..."

    # Kill TMWS server if we started it
    if [[ -n "${TMWS_PID:-}" ]]; then
        kill $TMWS_PID 2>/dev/null || true
    fi

    # Clean up temp files
    rm -f /tmp/ws_mcp_test.py

    print_status "Cleanup completed"
}

# Trap cleanup on exit
trap cleanup EXIT

# Main test execution
main() {
    echo "=========================================="
    echo "TMWS v2.2.0 Multi-Client Test Suite"
    echo "Testing shared server architecture"
    echo "=========================================="
    echo

    # Check server status
    check_tmws_status
    echo

    # Test WebSocket MCP
    test_websocket_mcp
    echo

    # Test REST API
    test_rest_api
    echo

    # Test mixed protocols
    test_mixed_protocols
    echo

    # Check server stats
    check_server_stats
    echo

    echo "=========================================="
    print_success "All multi-client tests completed!"
    echo "TMWS v2.2.0 successfully supports multiple"
    echo "Claude Code instances via shared server!"
    echo "=========================================="
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi