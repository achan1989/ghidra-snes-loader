package snesloader;

public interface RomInfoProvider {
	/**
	 * Gets the offset of the SNES header, in ROM space.
	 */
	long getSnesHeaderOffset();
	long getMaxRomSize();
	long getChunkSize();
	RomLoader getLoaderFunction();
}
