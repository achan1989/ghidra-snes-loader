package snesloader;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

public class RomInfo {

	public static final int SMC_HEADER_LEN = 512;

	public enum RomKind {
		LO_ROM(new LoRomLoader()),
		HI_ROM(new HiRomLoader());

		private final RomInfoProvider infoProvider;

		RomKind(RomInfoProvider infoProvider) {
			this.infoProvider = infoProvider;
		}

		private long getSnesHeaderOffset() {
			return infoProvider.getSnesHeaderOffset();
		}

		private long getMaxRomSize() {
			return infoProvider.getMaxRomSize();
		}

		private long getRomChunkSize() {
			return infoProvider.getChunkSize();
		}

		private RomLoader getLoader() {
			return infoProvider.getLoaderFunction();
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
			long romLen = provider.length() - getStartOffset();
			// Must contain at least one chunk.
			if (romLen < getRomChunkSize()) {
				looksValid = false;
			}
			// ROM dumps should be a multiple of this chunk size (SMC header excepted). 
			if (romLen % getRomChunkSize() != 0) {
				looksValid = false;
			}
			// Too big to load.
			if (romLen > kind.getMaxRomSize()) {
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

	public long getRomChunkSize() {
		return kind.getRomChunkSize();
	}

	public String getDescription() {
		return kind.toString() +
			(hasSmcHeader ? " with SMC header" : "");
	}

	public RomLoader getLoader() {
		return kind.getLoader();
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
