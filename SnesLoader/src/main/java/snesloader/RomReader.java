package snesloader;

import java.util.Iterator;
import java.util.NoSuchElementException;

import ghidra.app.util.bin.ByteProvider;
import org.apache.commons.lang3.tuple.ImmutablePair;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class RomReader implements Iterable<RomReader.RomChunk> {
	private RomInfo romInfo;
	private ByteProvider provider;

	public RomReader(RomInfo romInfo, ByteProvider provider) {
		this.romInfo = romInfo;
		this.provider = provider;
	}

	@Override
	public Iterator<RomChunk> iterator() {
		return new RomChunkIterator();
	}

	private class RomChunkIterator implements Iterator<RomChunk> {
		private int nextChunkIdx;

		public RomChunkIterator() {
			nextChunkIdx = 0;
		}

		private ImmutablePair<Long, Long> getNextChunkOffsets() {
			long nextChunkStartOffset = romInfo.getStartOffset() + (nextChunkIdx * romInfo.getRomChunkSize());
			long nextChunkEndOffset = (nextChunkStartOffset + romInfo.getRomChunkSize()) - 1;
			return ImmutablePair.of(nextChunkStartOffset, nextChunkEndOffset);
		}

		@Override
		public boolean hasNext() {
			var nextChunkOffsets = getNextChunkOffsets();
			return provider.isValidIndex(nextChunkOffsets.right);
		}

		@Override
		public RomChunk next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			var nextChunkOffsets = getNextChunkOffsets();
			nextChunkIdx++;
			return new RomChunk(nextChunkOffsets.left, nextChunkOffsets.right);
		}
	}

	public class RomChunk {
		private long providerStartOffset;
		private long providerEndOffset;
		private long length;
		private byte[] bytes;

		public RomChunk(long providerStartOffset, long providerEndOffset) {
			this.providerStartOffset = providerStartOffset;
			this.providerEndOffset = providerEndOffset;
			this.length = (providerEndOffset - providerStartOffset) + 1;
			this.bytes = null;
		}

		public InputStream getInputStream() throws IOException {
			if (bytes == null) {
				bytes = provider.readBytes(providerStartOffset, length);
			}
			return new ByteArrayInputStream(bytes);
		}

		public ImmutablePair<Long, Long> getRomAddresses() {
			long smcHeader = romInfo.getStartOffset();
			return ImmutablePair.of(providerStartOffset - smcHeader, providerEndOffset - smcHeader);
		}

		public long getLength() {
			return length;
		}
	}
}
