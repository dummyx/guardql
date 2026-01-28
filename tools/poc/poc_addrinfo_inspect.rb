#!/usr/bin/env ruby
# Stress Addrinfo#inspect with GC compaction (addrinfo_inspect).

require_relative "poc_utils"
POC.add_build_load_path
require "socket"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i

addrinfos = Addrinfo.getaddrinfo("localhost", 80, nil, nil, nil, Socket::AI_CANONNAME)

# Ensure canonname is present for at least one entry.
if addrinfos.none? { |ai| ai.canonname }
  warn "no canonname entries found; Addrinfo#inspect may not hit the risky path"
end

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    addrinfos.each(&:inspect)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
