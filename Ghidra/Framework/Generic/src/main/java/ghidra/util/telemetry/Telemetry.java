/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.util.telemetry;

import java.io.*;
import java.lang.management.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Periodic status reports for long unattended runs (headless analysis, batch decompiles), so
 * that what Ghidra is doing can be seen at any time.
 * <p>
 * Enabled by the environment variable {@code GHIDRA_TELEMETRY} (or the system property
 * {@code ghidra.telemetry}):
 * <ul>
 * <li>{@code log}: a one-line summary in the log every interval;</li>
 * <li>a file path: the same summary in the log, and one JSON object per report appended to
 * the file.</li>
 * </ul>
 * {@code GHIDRA_TELEMETRY_INTERVAL} (or {@code ghidra.telemetry.interval}) sets the seconds
 * between reports (default 30).
 * <p>
 * A report holds the current phase, the JVM heap, process CPU, free physical memory, the
 * decompiler processes, the progress of the {@link #monitor() telemetry monitor}, and every
 * activity in progress ({@link #begin}) with its running time.  When disabled, every call is
 * a cheap no-op.
 */
public final class Telemetry {

	private static final String SETTING = setting("GHIDRA_TELEMETRY", "ghidra.telemetry");

	/** True when reports are enabled */
	public static final boolean ENABLED = SETTING != null && !SETTING.isBlank();

	private static final long START = System.nanoTime();
	private static final AtomicLong IDS = new AtomicLong();
	private static final Map<Long, Activity> ACTIVE = new ConcurrentHashMap<>();
	private static final Activity NONE = new Activity(0, null, null, null, false);

	private static volatile String phase = "";
	private static volatile ProgressMonitor monitor;
	private static volatile Thread reporter;
	private static long lastCpuNanos = -1;
	private static long lastReportNanos;

	private Telemetry() {
	}

	/**
	 * Something in progress; it appears in every report until closed.
	 */
	public static final class Activity implements AutoCloseable {
		private final long id;
		private final String kind;
		private final String detail;
		private final Supplier<String> extra;
		private final boolean showFrame;
		private final long start = System.nanoTime();
		private final Thread thread = Thread.currentThread();

		private Activity(long id, String kind, String detail, Supplier<String> extra,
				boolean showFrame) {
			this.id = id;
			this.kind = kind;
			this.detail = detail;
			this.extra = extra;
			this.showFrame = showFrame;
		}

		@Override
		public void close() {
			if (id != 0) {
				ACTIVE.remove(id);
			}
		}
	}

	/**
	 * Start an activity, to be closed when it ends (try-with-resources).
	 * @param kind short category, such as "analyzer" or "decompile"
	 * @param detail what is being worked on
	 * @param extra optional; called at each report for live details (may be null)
	 * @param showFrame true to show where the activity's thread is executing
	 * @return the activity
	 */
	public static Activity begin(String kind, String detail, Supplier<String> extra,
			boolean showFrame) {
		if (!ENABLED) {
			return NONE;
		}
		start();
		Activity a = new Activity(IDS.incrementAndGet(), kind, detail, extra, showFrame);
		ACTIVE.put(a.id, a);
		return a;
	}

	/**
	 * Set the current phase (for example "import", "analysis", "script X")
	 * @param name the phase
	 */
	public static void phase(String name) {
		if (ENABLED) {
			start();
			phase = name;
			Msg.info(Telemetry.class, "TELEMETRY phase: " + name);
		}
	}

	/**
	 * A monitor whose message and progress appear in the reports, for code that otherwise
	 * gets {@link TaskMonitor#DUMMY}.
	 * @return the monitor, or {@link TaskMonitor#DUMMY} when disabled
	 */
	public static synchronized TaskMonitor monitor() {
		if (!ENABLED) {
			return TaskMonitor.DUMMY;
		}
		start();
		if (monitor == null) {
			monitor = new ProgressMonitor();
		}
		return monitor;
	}

	/**
	 * Start the periodic reports (once; later calls do nothing).  The first
	 * {@link #begin}, {@link #phase} or {@link #monitor} call starts them.
	 */
	public static void start() {
		if (!ENABLED || reporter != null) {
			return;
		}
		synchronized (Telemetry.class) {
			if (reporter == null) {
				startReporter();
			}
		}
	}

	private static void startReporter() {
		long seconds = 30;
		String s = setting("GHIDRA_TELEMETRY_INTERVAL", "ghidra.telemetry.interval");
		if (s != null) {
			try {
				seconds = Math.max(1, Long.parseLong(s.trim()));
			}
			catch (NumberFormatException e) {
				Msg.warn(Telemetry.class, "Bad GHIDRA_TELEMETRY_INTERVAL: " + s);
			}
		}
		long interval = seconds * 1000;
		File file = SETTING.trim().equalsIgnoreCase("log") ? null : new File(SETTING.trim());
		reporter = new Thread(() -> {
			while (true) {
				try {
					Thread.sleep(interval);
					report(file);
				}
				catch (InterruptedException e) {
					return;
				}
				catch (Throwable t) {
					Msg.warn(Telemetry.class, "Telemetry report failed: " + t);
				}
			}
		}, "Telemetry");
		reporter.setDaemon(true);
		reporter.start();
		Msg.info(Telemetry.class, "TELEMETRY every " + seconds + " s" +
			(file != null ? ", JSON lines to " + file.getAbsolutePath() : ""));
	}

	private static void report(File file) throws IOException {
		long now = System.nanoTime();
		StringBuilder line = new StringBuilder("TELEMETRY ");
		StringBuilder json = new StringBuilder("{");
		long elapsed = (now - START) / 1_000_000_000L;
		line.append(String.format("%d:%02d:%02d", elapsed / 3600, elapsed / 60 % 60, elapsed % 60));
		field(json, "time", Instant.now().toString());
		number(json, "elapsed_s", elapsed);
		if (!phase.isEmpty()) {
			line.append(" [").append(phase).append(']');
			field(json, "phase", phase);
		}

		MemoryUsage heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
		line.append(String.format(" heap %.1f/%.1f GB", gb(heap.getUsed()), gb(heap.getMax())));
		number(json, "heap_used_mb", heap.getUsed() >> 20);
		number(json, "heap_max_mb", heap.getMax() >> 20);
		OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
		if (os instanceof com.sun.management.OperatingSystemMXBean sun) {
			long cpu = sun.getProcessCpuTime();
			if (lastCpuNanos >= 0 && now > lastReportNanos) {
				double cores = (cpu - lastCpuNanos) / (double) (now - lastReportNanos);
				line.append(String.format(", java cpu %.1f cores", cores));
				json.append(String.format(Locale.ROOT, "\"java_cpu_cores\":%.2f,", cores));
			}
			lastCpuNanos = cpu;
			line.append(String.format(", free %.1f GB", gb(sun.getFreeMemorySize())));
			number(json, "free_memory_mb", sun.getFreeMemorySize() >> 20);
		}
		lastReportNanos = now;

		// decompiler (and other) child processes: per process in the JSON, by name in the line
		List<String> children = new ArrayList<>();
		Map<String, Integer> byName = new TreeMap<>();
		ProcessHandle.current().descendants().forEach(p -> {
			ProcessHandle.Info info = p.info();
			String name = info.command().map(c -> new File(c).getName()).orElse("?");
			long cpuS = info.totalCpuDuration().map(d -> d.toSeconds()).orElse(-1L);
			children.add(name + " pid " + p.pid() + (cpuS >= 0 ? " cpu " + cpuS + " s" : ""));
			byName.merge(name, 1, Integer::sum);
		});
		if (!byName.isEmpty()) {
			StringJoiner names = new StringJoiner(", ", ", children: ", "");
			byName.forEach((name, n) -> names.add(n > 1 ? name + " x" + n : name));
			line.append(names);
		}
		list(json, "children", children);

		ProgressMonitor m = monitor;
		if (m != null && m.getMessage() != null) {
			String progress = m.getMaximum() > 0 ? " " + m.getProgress() + "/" + m.getMaximum() : "";
			line.append(" | monitor: ").append(m.getMessage()).append(progress);
			field(json, "monitor", m.getMessage());
			number(json, "progress", m.getProgress());
			number(json, "maximum", m.getMaximum());
		}

		List<Activity> acts = new ArrayList<>(ACTIVE.values());
		acts.sort(Comparator.comparingLong(a -> a.start));
		List<String> items = new ArrayList<>();
		for (Activity a : acts) {
			StringBuilder b = new StringBuilder();
			b.append(a.kind).append(' ').append(a.detail).append(' ');
			b.append((now - a.start) / 1_000_000_000L).append(" s");
			if (a.extra != null) {
				try {
					String x = a.extra.get();
					if (x != null && !x.isEmpty()) {
						b.append(", ").append(x);
					}
				}
				catch (RuntimeException e) {
					// the activity may have just ended
				}
			}
			if (a.showFrame) {
				String frame = frame(a.thread);
				if (frame != null) {
					b.append(", at ").append(frame);
				}
			}
			items.add(b.toString());
		}
		for (String item : items) {
			line.append(" | ").append(item);
		}
		list(json, "activities", items);
		json.setLength(json.length() - 1);
		json.append("}\n");

		Msg.info(Telemetry.class, line.toString());
		if (file != null) {
			try (Writer w = new OutputStreamWriter(new FileOutputStream(file, true),
				StandardCharsets.UTF_8)) {
				w.write(json.toString());
			}
		}
	}

	/** The innermost frame of the thread outside the JDK, as Class.method:line */
	private static String frame(Thread t) {
		for (StackTraceElement e : t.getStackTrace()) {
			String c = e.getClassName();
			if (c.startsWith("java.") || c.startsWith("jdk.") || c.startsWith("sun.") ||
				c.startsWith("ghidra.util.")) {
				continue;
			}
			return c.substring(c.lastIndexOf('.') + 1) + "." + e.getMethodName() + ":" +
				e.getLineNumber();
		}
		return null;
	}

	private static double gb(long bytes) {
		return bytes / (1024.0 * 1024 * 1024);
	}

	private static void field(StringBuilder json, String key, String value) {
		json.append('"').append(key).append("\":").append(quote(value)).append(',');
	}

	private static void number(StringBuilder json, String key, long value) {
		json.append('"').append(key).append("\":").append(value).append(',');
	}

	private static void list(StringBuilder json, String key, List<String> values) {
		json.append('"').append(key).append("\":[");
		for (int i = 0; i < values.size(); i++) {
			json.append(i == 0 ? "" : ",").append(quote(values.get(i)));
		}
		json.append("],");
	}

	private static String quote(String s) {
		StringBuilder b = new StringBuilder("\"");
		for (char c : s.toCharArray()) {
			switch (c) {
				case '"' -> b.append("\\\"");
				case '\\' -> b.append("\\\\");
				case '\n' -> b.append("\\n");
				case '\r' -> b.append("\\r");
				case '\t' -> b.append("\\t");
				default -> {
					if (c < 0x20) {
						b.append(String.format("\\u%04x", (int) c));
					}
					else {
						b.append(c);
					}
				}
			}
		}
		return b.append('"').toString();
	}

	private static String setting(String env, String property) {
		String v = System.getProperty(property);
		return v != null ? v : System.getenv(env);
	}

	/** A monitor that keeps its message and progress for the reports */
	private static final class ProgressMonitor extends TaskMonitorAdapter {
		private volatile String message;
		private volatile long progress;
		private volatile long maximum;

		@Override
		public void setMessage(String msg) {
			message = msg;
		}

		@Override
		public String getMessage() {
			return message;
		}

		@Override
		public void initialize(long max) {
			maximum = max;
			progress = 0;
		}

		@Override
		public void setMaximum(long max) {
			maximum = max;
		}

		@Override
		public long getMaximum() {
			return maximum;
		}

		@Override
		public void setProgress(long value) {
			progress = value;
		}

		@Override
		public void incrementProgress(long amount) {
			progress += amount;
		}

		@Override
		public long getProgress() {
			return progress;
		}
	}
}
