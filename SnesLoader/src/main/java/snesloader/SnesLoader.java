package snesloader;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageCompilerSpecQuery;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.ProcessorNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SnesLoader extends AbstractProgramLoader {

	public static final String APPLY_SNES_LABELS_OPTION_NAME = "Apply SNES-specific Labels";
	public static final String ANCHOR_SNES_LABELS_OPTION_NAME = "Anchor SNES-specific Labels";
	public static final int SMC_HEADER_LEN = 512;
	public static final int SNES_HEADER_OFFSET_LOROM = 0x7FC0;
	public static final int SNES_HEADER_OFFSET_HIROM = 0xFFC0;
	public static final Integer SIXTEEN_BIT = 16;

	@Override
	public String getName() {
		// This name must match the name of the loader in the .opinion files.
		return "SNES ROM";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return false;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		getLanguageService();  // Ensure Processors are loaded.
		Processor snesProcessor;
		try {
			snesProcessor = Processor.toProcessor("65816");
		} catch (ProcessorNotFoundException e) {
			return loadSpecs;
		}

		boolean foundValidHeader = false;
		long[] headerLocations = new long[] {
			SNES_HEADER_OFFSET_LOROM,
			SNES_HEADER_OFFSET_HIROM,
			SMC_HEADER_LEN + SNES_HEADER_OFFSET_LOROM,
			SMC_HEADER_LEN + SNES_HEADER_OFFSET_HIROM};

		for (long location : headerLocations) {
			try {
				SnesHeader header = SnesHeader.fromProviderAtOffset(provider, location);
				if (header.looksValid()) {
					foundValidHeader = true;
					break;
				}
			} catch (IOException e) {
				continue;
			}
		}

		if (foundValidHeader) {
			LanguageCompilerSpecQuery query = new LanguageCompilerSpecQuery(
				snesProcessor, Endian.LITTLE, SIXTEEN_BIT, null, null);
			List<LanguageCompilerSpecPair> lcsps =
				getLanguageService().getLanguageCompilerSpecPairs(query);
			for (LanguageCompilerSpecPair lcsp : lcsps) {
				loadSpecs.add(new LoadSpec(this, 0, lcsp, false));
			}
		}

		return loadSpecs;
	}

	@Override
	protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program prog, TaskMonitor monitor,
			MemoryConflictHandler handler) {
		return false;
	}

	@Override
	protected List<Program> loadProgram(ByteProvider provider, String programName,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException {
		// TODO: load from provider into a new program.
		throw new IOException("snes loadProgram() not implemented yet");
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new Option(APPLY_SNES_LABELS_OPTION_NAME, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-applySnesLabels"));
		list.add(new Option(ANCHOR_SNES_LABELS_OPTION_NAME, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-anchorSnesLabels"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {
		String error = super.validateOptions(provider, loadSpec, options);
		
		if (error == null && options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(APPLY_SNES_LABELS_OPTION_NAME) ||
					name.equals(ANCHOR_SNES_LABELS_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						error = "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return error;
	}
}
