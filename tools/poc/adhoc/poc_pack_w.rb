# Ad-hoc PoC (moved from repo root).

GC.verify_compaction_references = true if GC.respond_to?(:verify_compaction_references=)
GC.auto_compact = true if GC.respond_to?(:auto_compact=)
begin
  GC.stress = :immediate
rescue ArgumentError, TypeError
  GC.stress = true
end

stop = false

Thread.new do
  until stop
    GC.compact if GC.respond_to?(:compact)
    GC.start(full_mark: true, immediate_sweep: true)
  end
end

Thread.new do
  until stop
    junk = []
    500.times { junk << ("x" * 2048) }
    junk.shuffle!
  end
end

data = Array.new(50_000, 0)

begin
  loop do
    data.pack("w*")
  end
ensure
  stop = true
end
