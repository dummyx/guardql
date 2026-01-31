#!/usr/bin/env ruby
# Stress ArithmeticSequence#inspect (enumerator.c:arith_seq_inspect) under heavy GC compaction.
#
# Run with: /path/to/ruby tools/poc/poc_arith_seq_inspect.rb

STDOUT.sync = true
Thread.report_on_exception = true

if GC.respond_to?(:verify_compaction_references=)
  GC.verify_compaction_references = true
end
if GC.respond_to?(:auto_compact=)
  GC.auto_compact = true
end

begin
  GC.stress = :immediate
rescue ArgumentError, TypeError
  GC.stress = true
end

duration = (ENV["POC_SECONDS"] || "30").to_i
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + duration

gc_thread = Thread.new do
  loop do
    GC.compact if GC.respond_to?(:compact)
    GC.start(full_mark: true, immediate_sweep: true)
  end
end

alloc_thread = Thread.new do
  loop do
    junk = Array.new(200) { "x" * 1024 }
    junk.shuffle!
  end
end

iterations = 0
while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
  1.step(10, 2).inspect
  iterations += 1
  puts "iterations=#{iterations}" if (iterations % 1000).zero?
end

gc_thread.kill
alloc_thread.kill

puts "done iterations=#{iterations}"

