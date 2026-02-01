# Standalone PoC for a missing-guard candidate in `rb_str_format_m`
# (String#% formatting path).
#
# Run with:
#   /path/to/ruby tools/poc/poc_rb_str_format_m.rb
#
# Tuning:
# - POC_SECONDS=60
# - POC_GC_STRESS_MODE=immediate
# - POC_ALLOC_HAMMER=1
# - POC_GC_HAMMER_FULL=1
# - POC_GC_HAMMER_COMPACT=1

require_relative "poc_utils"

seconds = (ENV["POC_SECONDS"] || "60").to_f

POC.setup_gc
gc_thread = POC.start_gc_hammer
alloc_thread = POC.start_alloc_hammer

class EvilToS
  def initialize(tag)
    @tag = tag
  end

  def to_s
    50.times { "x" * 10_000 }
    GC.start(full_mark: true, immediate_sweep: true)
    GC.compact if GC.respond_to?(:compact)
    "EVIL#{@tag}"
  end
end

class WrapToAry
  def initialize(i)
    @i = i
  end

  def to_ary
    [EvilToS.new(@i), EvilToS.new(@i + 1)]
  end
end

fmt = "%s-%s"

start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
iterations = 0
while (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) < seconds
  fmt % WrapToAry.new(iterations)
  iterations += 1
end

puts "done iterations=#{iterations}"
gc_thread&.kill
alloc_thread&.kill

