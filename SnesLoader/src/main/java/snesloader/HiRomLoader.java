package snesloader;

import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class HiRomLoader {

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log, Program prog,
			TaskMonitor monitor, RomInfo romInfo) {
		throw new UnsupportedOperationException("Loading a HI_ROM format is not implemented yet.");
	}

}
