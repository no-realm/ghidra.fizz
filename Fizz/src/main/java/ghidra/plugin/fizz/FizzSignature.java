package ghidra.plugin.fizz;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.utilities.environment.BasicBlock;
import ghidra.utilities.memory.MemorySignature;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 15, 2019
 */
class FizzSignature {
  private MemorySignature signature;

  FizzSignature(Program program, ProgramSelection selection, String delimiter) {
    this.signature = new MemorySignature(program, selection.getFirstRange(), delimiter);
  }

  public String getSelectedSignature() {
    try {
      return signature.getSignature();
    } catch (Exception e) {
      return "couldn't create";
    }
  }

  public String getSelectedBlockSignature() {
    try {
      BasicBlock block = new BasicBlock(signature.getProgram(), signature.getMinAddress());
      MemorySignature sig =
          new MemorySignature(
              signature.getProgram(), block.getBasicBlock(), signature.getDelimiter());
      return sig.getSignature();
    } catch (Exception e) {
      return "couldn't create";
    }
  }

  public String getSelectedFunctionSignature() {
    try {
      Function function =
          signature
              .getProgram()
              .getFunctionManager()
              .getFunctionContaining(signature.getMinAddress());
      // first range is the function containing the address, rest are following functions after
      MemorySignature sig =
          new MemorySignature(
              signature.getProgram(), function.getBody().getFirstRange(), signature.getDelimiter());
      return sig.getSignature();
    } catch (Exception e) {
      return "couldn't create";
    }
  }
}
