# Standalone PoC for a missing-guard candidate in `append_method`
# (Ruby enumerator inspect path).
#
# Run with:
#   /path/to/ruby tools/poc/poc_append_method.rb
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

klass = Class.new do
  def initialize(tag)
    @tag = tag
  end

  def inspect
    50.times { "x" * 10_000 }
    GC.start(full_mark: true, immediate_sweep: true)
    GC.compact if GC.respond_to?(:compact)
    "EVIL#{@tag}"
  end
end

a1 = klass.new(1)
a2 = klass.new(2)
enum = (1..100).to_enum(:each_cons, a1, a2)

start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
iterations = 0
while (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) < seconds
  enum.inspect
  iterations += 1
end

puts "done iterations=#{iterations}"
gc_thread&.kill
alloc_thread&.kill

