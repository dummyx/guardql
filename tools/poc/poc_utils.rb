# Common helpers for GC-stress PoCs.
module POC
  def self.add_build_load_path
    ext_dir = File.expand_path("../../ruby/build-o3/.ext/x86_64-linux", __dir__)
    objspace_lib_dir = File.expand_path("../../ruby/ext/objspace/lib", __dir__)
    pathname_lib_dir = File.expand_path("../../ruby/ext/pathname/lib", __dir__)
    lib_dir = File.expand_path("../../ruby/lib", __dir__)
    build_dir = File.expand_path("../../ruby/build-o3", __dir__)
    $LOAD_PATH.unshift(ext_dir) if Dir.exist?(ext_dir)
    $LOAD_PATH.unshift(objspace_lib_dir) if Dir.exist?(objspace_lib_dir)
    $LOAD_PATH.unshift(pathname_lib_dir) if Dir.exist?(pathname_lib_dir)
    $LOAD_PATH.unshift(lib_dir) if Dir.exist?(lib_dir)
    $LOAD_PATH.unshift(build_dir) if Dir.exist?(build_dir)
  end

  def self.setup_gc
    add_build_load_path
    begin
      require "enc/trans/transdb"
    rescue LoadError
      # Optional: transcoders may be missing in this build.
    end
    if GC.respond_to?(:verify_compaction_references=)
      GC.verify_compaction_references = true
    end
    if GC.respond_to?(:auto_compact=)
      GC.auto_compact = true
    end
    GC.stress = true
    if ENV["POC_GC_STRESS_MODE"] == "immediate"
      begin
        GC.stress = :immediate
      rescue ArgumentError, TypeError
      end
    end
  end

  def self.start_gc_hammer
    Thread.new do
      loop do
        GC.compact if GC.respond_to?(:compact)
        GC.start(full_mark: true, immediate_sweep: true)
      end
    end
  end

  def self.start_alloc_hammer
    return unless ENV["POC_ALLOC_HAMMER"] == "1"

    count = (ENV["POC_ALLOC_COUNT"] || "200").to_i
    size = (ENV["POC_ALLOC_SIZE"] || "1024").to_i
    Thread.new do
      loop do
        junk = Array.new(count) { "x" * size }
        junk.shuffle!
      end
    end
  end

  def self.maybe_alloc_junk(iteration)
    return unless ENV["POC_GC_JUNK"] == "1"

    every = (ENV["POC_GC_JUNK_EVERY"] || "1").to_i
    return unless (iteration % every).zero?

    count = (ENV["POC_GC_JUNK_COUNT"] || "100").to_i
    size = (ENV["POC_GC_JUNK_SIZE"] || "512").to_i
    junk = Array.new(count) { "y" * size }
    junk.shuffle!
  end

  def self.run_for(seconds)
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    while (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) < seconds
      yield
    end
  end
end
