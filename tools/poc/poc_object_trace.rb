#!/usr/bin/env ruby
# Stress ObjectSpace allocation tracing (newobj_i) with GC compaction.

require_relative "poc_utils"
POC.add_build_load_path
require "objspace"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i

ObjectSpace.trace_object_allocations_start

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    # Use eval with a long filename to stress path handling in newobj_i.
    fname = "trace_path_" + ("a" * 10000)
    eval("Object.new", binding, fname, 1)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  ObjectSpace.trace_object_allocations_stop
  gc_thread.kill
end

puts "done iterations=#{iterations}"
