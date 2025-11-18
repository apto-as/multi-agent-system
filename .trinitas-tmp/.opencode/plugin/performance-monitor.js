/**
 * Performance Monitor Plugin for Open Code
 * Tracks execution times and resource usage
 * Version: 1.0.0
 */

export const PerformanceMonitor = async ({ project, client, $, directory, worktree }) => {
  console.log('📊 Trinitas Performance Monitor initialized');

  // Performance tracking state
  const metrics = {
    toolExecutions: [],
    sessionStart: Date.now(),
    memoryBaseline: process.memoryUsage()
  };

  // Helper to format duration
  const formatDuration = (ms) => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms/1000).toFixed(1)}s`;
    return `${(ms/60000).toFixed(1)}m`;
  };

  // Helper to format memory
  const formatMemory = (bytes) => {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1048576) return `${(bytes/1024).toFixed(1)}KB`;
    return `${(bytes/1048576).toFixed(1)}MB`;
  };

  return {
    // Monitor session events
    event: async ({ event }) => {
      if (event.type === 'session.start') {
        metrics.sessionStart = Date.now();
        metrics.memoryBaseline = process.memoryUsage();
        console.log('📊 Performance monitoring started');
      }

      if (event.type === 'session.idle') {
        const duration = Date.now() - metrics.sessionStart;
        const memoryNow = process.memoryUsage();
        const memoryDelta = memoryNow.heapUsed - metrics.memoryBaseline.heapUsed;

        console.log(`📊 Session metrics:`);
        console.log(`  Duration: ${formatDuration(duration)}`);
        console.log(`  Memory delta: ${formatMemory(memoryDelta)}`);
        console.log(`  Tool executions: ${metrics.toolExecutions.length}`);
      }
    },

    // Track tool execution performance
    "tool.execute.before": async (input, output) => {
      // Add timing metadata
      output._perfStart = Date.now();
      output._memStart = process.memoryUsage();
    },

    // Measure tool execution results
    "tool.execute.after": async (input, output) => {
      if (output._perfStart) {
        const duration = Date.now() - output._perfStart;
        const memDelta = process.memoryUsage().heapUsed - output._memStart.heapUsed;

        const metric = {
          tool: input.tool,
          duration: duration,
          memoryDelta: memDelta,
          timestamp: new Date().toISOString(),
          success: output.success !== false
        };

        metrics.toolExecutions.push(metric);

        // Log slow operations
        if (duration > 3000) {
          console.warn(`⚠️  Slow operation: ${input.tool} took ${formatDuration(duration)}`);
        }

        // Log memory-intensive operations
        if (memDelta > 50 * 1048576) { // 50MB
          console.warn(`⚠️  Memory spike: ${input.tool} used ${formatMemory(memDelta)}`);
        }

        // Clean up timing metadata
        delete output._perfStart;
        delete output._memStart;
      }
    },

    // Periodic metrics report
    "metrics.report": async () => {
      if (metrics.toolExecutions.length === 0) {
        return { message: "No metrics collected yet" };
      }

      // Calculate statistics
      const durations = metrics.toolExecutions.map(m => m.duration);
      const avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
      const maxDuration = Math.max(...durations);
      const minDuration = Math.min(...durations);

      const toolCounts = {};
      metrics.toolExecutions.forEach(m => {
        toolCounts[m.tool] = (toolCounts[m.tool] || 0) + 1;
      });

      return {
        summary: {
          totalExecutions: metrics.toolExecutions.length,
          avgDuration: formatDuration(avgDuration),
          maxDuration: formatDuration(maxDuration),
          minDuration: formatDuration(minDuration),
          sessionDuration: formatDuration(Date.now() - metrics.sessionStart)
        },
        toolUsage: toolCounts,
        slowestOperations: metrics.toolExecutions
          .sort((a, b) => b.duration - a.duration)
          .slice(0, 5)
          .map(m => ({
            tool: m.tool,
            duration: formatDuration(m.duration),
            timestamp: m.timestamp
          }))
      };
    }
  };
};

// Export as default for compatibility
export default PerformanceMonitor;