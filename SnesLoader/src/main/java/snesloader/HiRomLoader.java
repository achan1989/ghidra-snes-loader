package snesloader;

import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class HiRomLoader implements RomInfoProvider {
	public static final long SNES_HEADER_OFFSET = 0xFFC0;
	public static final long MAX_ROM_SIZE = 0x40_0000;
	public static final int ROM_CHUNK_SIZE = 0x8000;

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log, Program prog,
			TaskMonitor monitor, RomInfo romInfo) {
		throw new UnsupportedOperationException("Loading a HI_ROM format is not implemented yet.");
	}

	@Override
	public long getSnesHeaderOffset() {
		return SNES_HEADER_OFFSET;
	}

	@Override
	public long getMaxRomSize() {
		return MAX_ROM_SIZE;
	}

	@Override
	public long getChunkSize() {
		return ROM_CHUNK_SIZE;
	}

	@Override
	public RomLoader getLoaderFunction() {
		return HiRomLoader::load;
	}
}
