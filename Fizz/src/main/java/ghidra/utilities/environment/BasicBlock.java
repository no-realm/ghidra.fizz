package ghidra.utilities.environment;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

/**
 * Class for finding, getting, and using basic assembly blocks
 *
 * @author quosego <https://github.com/quosego>
 * @version Mar 15, 2019
 */
public class BasicBlock {
  private Program program;

  private Address marker;

  private Address start;

  private Address end;

  // =============================================================================================
  // Constructors
  // =============================================================================================

  public BasicBlock(Program program, Address markerAddress) {
    setProgram(program);
    setMarker(markerAddress);
  }

  // =============================================================================================
  // Getter and Setter methods
  // =============================================================================================

  public Program getProgram() {
    return program;
  }

  public void setProgram(Program program) {
    this.program = program;
  }

  public Address getMarker() {
    return marker;
  }

  public void setMarker(Address address) {
    this.marker = address;
    findEndBlock();
    findStartBlock();
  }

  public Address getStartBlock() {
    return start;
  }

  public Address getEndBlock() {
    return end;
  }

  public AddressRange getBasicBlock() {
    return new AddressRangeImpl(getStartBlock(), getEndBlock());
  }

  // =============================================================================================
  // Block Creation methods
  // =============================================================================================

  private void findEndBlock() {
    this.end = null;
    Listing listing = getProgram().getListing();
    Address address = getMarker();
    Function function = getProgram().getFunctionManager().getFunctionContaining(marker);

    boolean isEndBlockFlag = false;
    while (address != null && isEndBlockFlag == false) {
      try {
        Instruction instruction = listing.getInstructionContaining(address);
        FlowType flow = instruction.getFlowType();

        if (flow.isJump() || flow.isTerminal()) {
          this.end = instruction.getAddress();
          isEndBlockFlag = true;
        }
        // TODO port from sail project

        address = instruction.getNext().getAddress();
      } catch (Exception e) {
        // step over address instead if not instruction
        address = getNextAddress(address);
      }
    }

    // might be just a single block function so apply
    // TODO port from sail project
    if (this.end == null && isInFunction(this.start)) {
      this.end = function.getBody().getRangeContaining(this.start).getMaxAddress();
    }
  }

  private void findStartBlock() {
    this.start = null;
    Listing listing = getProgram().getListing();
    Address min = getProgram().getMinAddress();
    Address address = getMarker();
    Function function = getProgram().getFunctionManager().getFunctionContaining(marker);
    Address functionAddressMin = function.getBody().getRangeContaining(getMarker()).getMinAddress();

    boolean isStartBlockFlag = false;
    while (address != null && isStartBlockFlag == false) {
      try {
        Instruction instruction = listing.getInstructionContaining(address);
        FlowType flow = instruction.getFlowType();

        if (flow.isJump() || flow.isTerminal()) {
          // start should be on after the end rather than on the end
          this.start = instruction.getNext().getAddress();
          isStartBlockFlag = true;
        } else if (address.equals(min) || address.equals(functionAddressMin)) {
          this.start = instruction.getAddress();
          isStartBlockFlag = true;
        } else if (hasReferencesToJump(instruction)) {
          this.start = instruction.getAddress();
          isStartBlockFlag = true;
        }
        // TODO port from sail project

        address = instruction.getPrevious().getAddress();
      } catch (Exception e) {
        // step over address instead if not instruction
        address = getPreviousAddress(address);
      }
    }

    // might be just a single block function so apply
    // TODO port from sail project
    if (this.start == null && isInFunction(this.start)) {
      this.start = function.getEntryPoint();
    }
  }

  // =============================================================================================
  // Instruction Iterator methods
  // =============================================================================================

  private Address getNextAddress(Address currentAddress) {
    if (currentAddress == null) {
      // can't do anything
      return null;
    }
    return currentAddress.equals(getProgram().getMaxAddress()) ? null : currentAddress.next();
  }

  private Address getPreviousAddress(Address currentAddress) {
    if (currentAddress == null) {
      // can't do anything
      return null;
    }
    return currentAddress.equals(getProgram().getMinAddress()) ? null : currentAddress.previous();
  }

  // =============================================================================================
  // Instruction References methods
  // =============================================================================================

  private boolean hasReferencesTo(Instruction instruction) {
    ReferenceIterator referencesTo = instruction.getReferenceIteratorTo();
    if (referencesTo.hasNext()) {
      return true;
    }
    return false;
  }

  private boolean hasReferencesToJump(Instruction instruction) {
    ReferenceIterator referencesTo = instruction.getReferenceIteratorTo();
    if (referencesTo.hasNext()) {
      Reference reference = referencesTo.next();
      if (reference.getReferenceType().isJump()) {
        return true;
      }
    }
    return false;
  }

  private boolean hasReferencesToIndirect(Instruction instruction) {
    ReferenceIterator referencesTo = instruction.getReferenceIteratorTo();
    if (referencesTo.hasNext()) {
      Reference reference = referencesTo.next();
      if (reference.getReferenceType().isIndirect()) {
        return true;
      }
    }
    return false;
  }

  private boolean hasReferencesFrom(Instruction instruction) {
    Reference[] referencesFrom = instruction.getReferencesFrom();
    if (referencesFrom.length > 0) {
      return true;
    }
    return false;
  }

  // =============================================================================================
  // Only Block is Function methods
  // =============================================================================================

  private boolean isInFunction(Address address) {
    if (address == null) {
      return false;
    }
    return getProgram().getListing().isInFunction(address);
  }
}
