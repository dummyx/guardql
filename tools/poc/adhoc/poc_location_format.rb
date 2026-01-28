# Ad-hoc PoC (moved from repo root).

GC.verify_compaction_references = true if GC.respond_to?(:verify_compaction_references=)
GC.auto_compact = true if GC.respond_to?(:auto_compact=)
begin
  GC.stress = :immediate
rescue ArgumentError, TypeError
  GC.stress = true
end

Thread.new do
  loop do
    GC.compact if GC.respond_to?(:compact)
    GC.start(full_mark: true, immediate_sweep: true)
  end
end

Thread.new do
  loop do
    junk = []
    200.times { junk << ("x" * 1024) }
    junk.shuffle!
  end
end

eval(<<~'RUBY', binding, "a", 1)
  def x
    begin
      raise "boom"
    rescue => e
      e.backtrace_locations.each do |loc|
        loc.to_s
      end
    end
  end
RUBY

loop do
  x
end
