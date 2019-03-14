package ghidra.utilities.memory;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Class for creating signatures from a set of addresses (start, end)
 *
 * @author quosego <https://github.com/quosego>
 * @version Mar 13, 2019
 */
public class MemorySignature extends AddressSet {
  private Listing listing;

  private String signature;

  public MemorySignature(AddressRange range) {
    super(range);
  }

  public MemorySignature(Address start, Address end) {
    super(start, end);
  }

  public MemorySignature(Program program, Address start, Address end) {
    super(program, start, end);
    this.listing = program.getListing();
  }

  public String getSignature() {
    return signature;
  }

  public void setSignature(String signature) {
    this.signature = signature;
  }

  private void buildSignature() {
    StringBuilder bytes = new StringBuilder();
    // only one selection per context at time so can pull just the first

    InstructionIterator instructionIterator = listing.getInstructions(this, true);
    // iterate instructions in address set
    while (instructionIterator.hasNext()) {

      Instruction instruction = instructionIterator.next();

      try {
        // first byte of the the mnemonic
        //bytes.append(convertByteToString(instruction.getByte(0))).append(getSpacer());
        // following bytes
        //bytes.append(getBytesTrailingFromMnemonic(instruction));

      } catch (MemoryAccessException e) {
        // can't do anything
      }
    }
    setSignature(bytes.toString());
  }
}
