#!/usr/bin/env ruby
# Stress StringifySymbols.stringify_symbol under GC compaction.

require_relative "poc_utils"
POC.add_build_load_path
require "-test-/load/stringify_symbols"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i

lib = (ENV["POC_LIB"] || "libc.so.6")
name = (ENV["POC_SYMBOL"] || "printf")

# Enlarge inputs to force heavy string handling.
lib = (lib + "_x" * 4096)
name = (name + "_y" * 4096)

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    StringifySymbols.stringify_symbol(lib, name)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
