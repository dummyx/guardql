#!/usr/bin/env ruby
# Standalone PoC for rb_deflate_params under heavy GC pressure.

require "zlib"

STDOUT.sync = true

GC.stress = :immediate rescue nil

seconds = 180
producer_threads = 2
param_threads = 2
payload_size = 1024 * 1024
junk_count = 800
junk_size = 4096
inner_rounds = 20

stop = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds

gc_thread = Thread.new do
  while Process.clock_gettime(Process::CLOCK_MONOTONIC) < stop
    GC.compact if GC.respond_to?(:compact)
    GC.start(full_mark: true, immediate_sweep: true)
  end
end

alloc_thread = Thread.new do
  while Process.clock_gettime(Process::CLOCK_MONOTONIC) < stop
    junk = Array.new(junk_count) { "x" * junk_size }
    junk.shuffle!
  end
end

deflater = Zlib::Deflate.new

producers = []
producer_threads.times do |tid|
  producers << Thread.new do
    iterations = 0
    while Process.clock_gettime(Process::CLOCK_MONOTONIC) < stop
      inner_rounds.times do |round|
        payload = "a" * (payload_size + ((iterations + round) % 1024))
        deflater << payload
        deflater.flush
      end
      junk = Array.new(junk_count / 2) { "y" * (junk_size / 2) }
      junk.shuffle!
      iterations += 1
    end
    puts "producer #{tid} done iterations=#{iterations}"
  end
end

param_runners = []
param_threads.times do |tid|
  param_runners << Thread.new do
    iterations = 0
    while Process.clock_gettime(Process::CLOCK_MONOTONIC) < stop
      if (iterations % 2).zero?
        deflater.params(Zlib::BEST_SPEED, Zlib::DEFAULT_STRATEGY)
      else
        deflater.params(Zlib::BEST_COMPRESSION, Zlib::FILTERED)
      end
      iterations += 1
    end
    puts "params #{tid} done iterations=#{iterations}"
  end
end

gc_thread.kill
alloc_thread.kill
producers.each(&:join)
param_runners.each(&:join)
begin
  deflater.finish
ensure
  deflater.close rescue nil
end
puts "done"
