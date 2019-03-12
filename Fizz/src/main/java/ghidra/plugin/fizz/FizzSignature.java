package ghidra.plugin.fizz;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramSelection;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 11, 2019
 */
class FizzSignature {
  private Memory memory;
  private Listing listing;
  private ProgramSelection selection;

  private String raw;
  private String signature;

  private String delimiter;
  private String spacer;

  FizzSignature(Program program, ProgramSelection selection, String delimiter) {
    setMemory(program.getMemory());
    setListing(program.getListing());
    setDelimiter(delimiter);
    setSpacer(" ");
    setSelection(selection);
    setRaw(getBytesFromAddressRange());
    setSignature(getSignatureFromAddressRange());
  }

  // =============================================================================================
  // Getter and Setter methods
  // =============================================================================================

  String getRaw() {
    return this.raw;
  }

  private void setRaw(String raw) {
    this.raw = raw;
  }

  String getSignature() {
    return this.signature;
  }

  private void setSignature(String signature) {
    this.signature = signature;
  }

  private void setMemory(Memory memory) {
    this.memory = memory;
  }

  private void setListing(Listing listing) {
    this.listing = listing;
  }

  private void setDelimiter(String delimiter) {
    this.delimiter = delimiter;
  }

  private String getDelimiter() {
    return this.delimiter;
  }

  private void setSelection(ProgramSelection selection) {
    this.selection = selection;
  }

  private void setSpacer(String spacer) {
    this.spacer = spacer;
  }

  private String getSpacer() {
    return this.spacer;
  }

  // =============================================================================================
  // Iterator Helper methods
  // =============================================================================================

  private Address getNextAddress(Address currentAddress, AddressRange range) {
    if (currentAddress == null) {
      // can't do anything
      return null;
    }
    // traverse forwards till null
    return currentAddress.equals(range.getMaxAddress()) ? null : currentAddress.next();
  }

  // =============================================================================================
  // Formatting / Padding Helper methods
  // =============================================================================================

  private String convertByteToString(byte b) {
    return String.format("%02X ", b);
  }

  private String createPaddingAtFor(int offset, int length) {
    StringBuilder bytes = new StringBuilder();
    for (int i = offset; i < length; i++) {
      bytes.append(getDelimiter()).append(getSpacer());
    }
    return bytes.toString();
  }

  private String getBytesTrailingFromMnemonic(Instruction instruction) {
    String bytesTrailing = "";
    try {
      switch (instruction.getLength()) {
        case 2: // X ??
        case 5: // X ?? ?? ?? ??
          bytesTrailing += createPaddingAtFor(1, instruction.getLength());
          break;
        case 3: // X X ??
        case 4: // X X ?? ??
        case 6: // X X ?? ?? ?? ??
          bytesTrailing += convertByteToString(instruction.getByte(1)) + getSpacer();
          bytesTrailing += createPaddingAtFor(2, instruction.getLength());
          break;
        case 7: // X X X ?? ?? ?? ??
        case 8: // X X X ?? ?? ?? ?? ??
          bytesTrailing += convertByteToString(instruction.getByte(1)) + getSpacer();
          bytesTrailing += convertByteToString(instruction.getByte(2)) + getSpacer();
          bytesTrailing += createPaddingAtFor(3, instruction.getLength());
          break;
        default:
          bytesTrailing += createPaddingAtFor(1, instruction.getLength());
          break;
      }
    } catch (MemoryAccessException e) {
      // can't do anything so reset and set as unknown
      bytesTrailing += createPaddingAtFor(1, instruction.getLength());
    }
    return bytesTrailing;
  }

  // =============================================================================================
  // Signature Making Helper methods
  // =============================================================================================

  private String getBytesFromAddressRange() {
    StringBuilder bytes = new StringBuilder();
    // only one selection per context at time so can pull just the first
    AddressRange range = this.selection.getFirstRange();
    Address start = range.getMinAddress();
    while (start != null) {
      try {
        bytes.append(convertByteToString(this.memory.getByte(start))).append(getSpacer());
      } catch (MemoryAccessException e) {
        // can't do anything
      }
      start = getNextAddress(start, range);
    }
    return bytes.toString();
  }

  private String getSignatureFromAddressRange() {
    StringBuilder bytes = new StringBuilder();
    // only one selection per context at time so can pull just the first
    AddressSet address = new AddressSet(this.selection.getFirstRange());
    InstructionIterator instructionIterator = listing.getInstructions(address, true);
    // iterate instructions in address set
    while (instructionIterator.hasNext()) {

      Instruction instruction = instructionIterator.next();

      try {
        // first byte of the the mnemonic
        bytes.append(convertByteToString(instruction.getByte(0))).append(getSpacer());
        // following bytes
        bytes.append(getBytesTrailingFromMnemonic(instruction));

      } catch (MemoryAccessException e) {
        // can't do anything
      }
    }
    return bytes.toString();
  }
}
