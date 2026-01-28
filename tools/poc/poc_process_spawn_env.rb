#!/usr/bin/env ruby
# Stress env packing for Process.spawn (fill_envp_buf_i) under GC compaction.

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i

key = "K" * 1024
val = "V" * 1024

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    pid = Process.spawn({ key => val }, "/bin/true")
    Process.wait(pid)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 50).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
