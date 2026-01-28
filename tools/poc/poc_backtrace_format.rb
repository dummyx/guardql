#!/usr/bin/env ruby
# Stress Thread::Backtrace::Location#to_s (location_format) with GC compaction.

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i
fname = "x" * (ENV["POC_FILENAME_SIZE"] || "1000000").to_i
code = "def boom; raise 'boom'; end; boom"

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    begin
      eval(code, binding, fname, 1)
    rescue => e
      e.backtrace_locations.each(&:to_s)
    end
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 50).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
