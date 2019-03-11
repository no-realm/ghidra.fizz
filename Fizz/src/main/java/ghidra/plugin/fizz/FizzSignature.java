package ghidra.plugin.fizz;

import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramSelection;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 10, 2019
 */
public class FizzSignature {
  private Program program;
  private Memory memory;
  private Listing listing;
  private ProgramSelection selection;

  private String raw;
  private String signature;

  private String delimiter;

  FizzSignature(Program program, ProgramSelection selection, String delimiter) {
    this.raw = "";
    this.signature = "";
    this.program = program;
    this.memory = program.getMemory();
    this.listing = program.getListing();
    this.selection = selection;
    this.delimiter = delimiter;

    setBytesFromAddressRange();
    setSignatureFromAddressRange();
  }

  private Address getNextAddress(Address currentAddress, AddressRange range) {
    if (currentAddress == null) {
      // can't do anything
      return null;
    }
    // traverse forwards till null
    return currentAddress.equals(range.getMaxAddress()) ? null : currentAddress.next();
  }

  private void setBytesFromAddressRange() {
    String bytes = "";
    // only one selection per context at time so can pull just the first
    AddressRange range = this.selection.getFirstRange();
    Address start = range.getMinAddress();
    while (start != null) {
      try {
        bytes += convertByteToString(this.memory.getByte(start)) + " ";
      } catch (MemoryAccessException e) {
        // can't do anything
        // isnt valid memory so set as unknown
      }
      start = getNextAddress(start, range);
    }
    this.raw = bytes;
  }

  private String createPaddingAtFor(int offset, int length) {
    String bytes = "";
    for (int i = offset; i < length; i++) {
      bytes += this.delimiter + " ";
    }
    return bytes;
  }

  private String getBytesTrailingFromMnemonic(Instruction instruction) {
    String bytesTrailing = "";
    try {
      switch (instruction.getLength()) {
          // else to 5
        case 2: // X ??
          bytesTrailing += createPaddingAtFor(1, instruction.getLength());
          break;
        case 5: // X ?? ?? ?? ??
          bytesTrailing += createPaddingAtFor(1, instruction.getLength());
          break;
        case 3: // X X ??
        case 4: // X X ?? ??
        case 6: // X X ?? ?? ?? ??
          bytesTrailing += convertByteToString(instruction.getByte(1)) + " ";
          bytesTrailing += createPaddingAtFor(2, instruction.getLength());
          break;
        case 7: // X X X ?? ?? ?? ??
        case 8: // X X X ?? ?? ?? ?? ??
          bytesTrailing += convertByteToString(instruction.getByte(1)) + " ";
          bytesTrailing += convertByteToString(instruction.getByte(2)) + " ";
          bytesTrailing += createPaddingAtFor(3, instruction.getLength());
          break;
        default:
          bytesTrailing += createPaddingAtFor(1, instruction.getLength());
          break;
      }
    } catch (MemoryAccessException e) {
      // can't do anything so reset and set as unknown
      bytesTrailing = "";
      bytesTrailing += createPaddingAtFor(1, instruction.getLength());
    }
    return bytesTrailing;
  }

  private void setSignatureFromAddressRange() {
    String bytes = "";
    // only one selection per context at time so can pull just the first
    AddressSet address = new AddressSet(this.selection.getFirstRange());
    InstructionIterator instructionIterator = listing.getInstructions(address, true);
    // iterate instructions in address set
    while (instructionIterator.hasNext()) {

      Instruction instruction = instructionIterator.next();

      try {
        // first byte of the the mnemonic
        bytes += convertByteToString(this.memory.getByte(instruction.getAddress())) + " ";

        bytes += getBytesTrailingFromMnemonic(instruction);

      } catch (MemoryAccessException e) {
        // can't do anything so reset and set as unknown
        bytes = "";
        for (int i = 1; i < instruction.getLength(); i++) {
          bytes += this.delimiter + " ";
        }
      }
    }
    this.signature = bytes;
  }

  private String convertByteToString(byte b) {
    StringBuilder sb = new StringBuilder();
    sb.append(String.format("%02X ", b));
    return sb.toString();
  }

  public String getSignature() {
    return this.signature;
  }

  public String getRaw() {
    return this.raw;
  }
}
