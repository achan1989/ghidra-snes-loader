package snesloader;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

public class RomInfo {

	public static final int SMC_HEADER_LEN = 512;
	public static final int SNES_HEADER_OFFSET_LOROM = 0x7FC0;
	public static final int SNES_HEADER_OFFSET_HIROM = 0xFFC0;
	// ROM is mapped in multiples of this chunk size. 
	public static final int MINIMUM_ROM_CHUNK_SIZE = 0x8000;

	public enum RomKind {
		LO_ROM(SNES_HEADER_OFFSET_LOROM),
		HI_ROM(SNES_HEADER_OFFSET_HIROM);

		private final long snesHeaderOffset;

		RomKind(long snesHeaderOffset) {
			this.snesHeaderOffset = snesHeaderOffset;
		}

		private long getSnesHeaderOffset() {
			return snesHeaderOffset;
		}
	}

	private RomKind kind;
	private boolean hasSmcHeader;

	public RomInfo(RomKind kind, boolean hasSmcHeader) {
		this.kind = kind;
		this.hasSmcHeader = hasSmcHeader;
	}

	public boolean bytesLookValid(ByteProvider provider) {
		boolean looksValid = true;
		try {
			long bytesLen = provider.length() - getStartOffset();
			if (bytesLen < MINIMUM_ROM_CHUNK_SIZE) {
				looksValid = false;
			}
			// ROM dumps should be a multiple of this chunk size (SMC header excepted). 
			if (bytesLen % MINIMUM_ROM_CHUNK_SIZE != 0) {
				looksValid = false;
			}

			SnesHeader snesHeader = SnesHeader.fromProviderAtOffset(provider, getSnesHeaderOffset());
			looksValid = looksValid && snesHeader.looksValid();
		} catch (IOException e) {
			looksValid = false;
		}

		return looksValid;
	}

	public long getStartOffset() {
		return (hasSmcHeader ? SMC_HEADER_LEN : 0);
	}

	public long getSnesHeaderOffset() {
		return getStartOffset() + kind.getSnesHeaderOffset();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (hasSmcHeader ? 1231 : 1237);
		result = prime * result + ((kind == null) ? 0 : kind.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RomInfo other = (RomInfo) obj;
		if (hasSmcHeader != other.hasSmcHeader)
			return false;
		if (kind != other.kind)
			return false;
		return true;
	}
}
