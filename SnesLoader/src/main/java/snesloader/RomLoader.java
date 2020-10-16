package snesloader;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

@FunctionalInterface
public interface RomLoader {
	public boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
		Program prog, TaskMonitor monitor, RomInfo romInfo) throws IOException;
}
