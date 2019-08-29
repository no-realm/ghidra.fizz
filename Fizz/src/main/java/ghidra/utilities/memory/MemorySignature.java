package ghidra.utilities.memory;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Class for creating generic memory signatures
 *
 * @author quosego <https://github.com/quosego>
 * @version Mar 15, 2019
 */
public class MemorySignature extends AddressSet {
    private Program program;
    
    private Listing listing;

    private Memory memory;

    private String signature;

    private String delimiter;

    private String spacer;

    // =============================================================================================
    // Constructors
    // =============================================================================================

    /**
     *
     * @param program
     * @param delimiter
     * @param spacer
     */
    public MemorySignature(Program program, String delimiter, String spacer) {
        super();
        setProgram(program);
        setDelimiter(delimiter);
        setSpacer(spacer);
    }

    public MemorySignature(Program program, String delimiter) {
        this(program, delimiter, " ");
    }

    public MemorySignature(Program program) {
        this(program, "..", " ");
    }

    /**
     *
     * @param program
     * @param address
     * @param delimiter
     * @param spacer
     */
    public MemorySignature(Program program, Address address, String delimiter, String spacer) {
        super(address);
        setProgram(program);
        setDelimiter(delimiter);
        setSpacer(spacer);
    }

    public MemorySignature(Program program, Address address, String delimiter) {
        this(program, address, delimiter, " ");
    }

    public MemorySignature(Program program, Address address) {
        this(program, address, "..", " ");
    }

    /**
     *
     * @param program
     * @param range
     * @param delimiter
     * @param spacer
     */
    public MemorySignature(Program program, AddressRange range, String delimiter, String spacer) {
        super(range);
        setProgram(program);
        setDelimiter(delimiter);
        setSpacer(spacer);
    }

    public MemorySignature(Program program, AddressRange range, String delimiter) {
        this(program, range, delimiter, " ");
    }

    public MemorySignature(Program program, AddressRange range) {
        this(program, range, "..", " ");
    }

    /**
     *
     * @param program
     * @param setview
     * @param delimiter
     * @param spacer
     */
    public MemorySignature(Program program, AddressSetView setview, String delimiter, String spacer) {
        super(setview);
        setProgram(program);
        setDelimiter(delimiter);
        setSpacer(spacer);
    }

    public MemorySignature(Program program, AddressSetView setview, String delimiter) {
        this(program, setview, delimiter, " ");
    }

    public MemorySignature(Program program, AddressSetView setview) {
        this(program, setview, "..", " ");
    }

    /**
     *
     * @param program
     * @param start
     * @param end
     * @param delimiter
     * @param spacer
     */
    public MemorySignature(Program program, Address start, Address end, String delimiter, String spacer) {
        super(program, start, end);
        setProgram(program);
        setDelimiter(delimiter);
        setSpacer(spacer);
    }

    public MemorySignature(Program program, Address start, Address end, String delimiter) {
        this(program, start, end, delimiter, " ");
    }

    public MemorySignature(Program program, Address start, Address end) {
        this(program, start, end, "..", " ");
    }

    // =============================================================================================
    // Getter and Setter methods
    // =============================================================================================

    public String getSignature() {
        buildSignature();
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getDelimiter() {
        return this.delimiter;
    }

    public void setDelimiter(String delimiter) {
        this.delimiter = delimiter;
    }

    private String getSpacer() {
        return this.spacer;
    }

    public void setSpacer(String spacer) {
        this.spacer = spacer;
    }

    public Listing getListing() {
        return this.listing;
    }

    private void setListing(Listing listing) {
        this.listing = listing;
    }

    public Memory getMemory() {
        return this.memory;
    }

    private void setMemory(Memory memory) {
        this.memory = memory;
    }

    public void setProgram(Program program) {
        setListing(program.getListing());
        setMemory(program.getMemory());
        this.program = program;
    }
    
    public Program getProgram() {
        return this.program;
    }

    // =============================================================================================
    // Signature Getter builders
    // =============================================================================================

    private void buildSignature() {
        setSignature(iterateAddresses());
    }

    // =============================================================================================
    // Signature Creation methods
    // =============================================================================================

    private String createInstructionSignature(Address address) throws MemoryAccessException {
        StringBuilder bytes = new StringBuilder();
        Instruction instruction = getListing().getInstructionAt(address);
        bytes.append(convertByteToString(instruction.getByte(0))).append(getSpacer());
        bytes.append(getBytesTrailingFromInstructionMnemonic(instruction));
        return bytes.toString();
    }
    
    private String createDataSignature(Address address) throws MemoryAccessException {
        StringBuilder bytes = new StringBuilder();
        Data data = getListing().getDataAt(address);
        for (int i = 0; i < data.getLength(); i++) {
            bytes.append(convertByteToString(data.getByte(i))).append(getSpacer()); 
        }
        return bytes.toString();
    }
    
    private String createCodeUnitSignature(Address address) throws MemoryAccessException {
        StringBuilder bytes = new StringBuilder();
        CodeUnit unit = getListing().getCodeUnitAt(address);
        for (int i = 0; i < unit.getLength(); i++) {
            bytes.append(convertByteToString(unit.getByte(i))).append(getSpacer()); 
        }
        return bytes.toString();
    }
    
    private String createAddressPaddedSignature(Address address) {
        return createPaddingAtFor(0, address.getSize());
    }

    // =============================================================================================
    // Instruction Signature Builder helpers
    // =============================================================================================

    private String getBytesTrailingFromInstructionMnemonic(Instruction instruction) {
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
    // Address Iteration methods
    // =============================================================================================

    private String iterateAddresses() {
        StringBuilder bytes = new StringBuilder();
        AddressIterator iterator = this.getAddresses(true);
        while (iterator.hasNext()) {
            Address address = iterator.next();
            if (address.compareTo(this.getMaxAddress()) > 0) {
                // if somehow larger than max address range
                break;
            }
            
            try {
                if (isInstructionAt(address)) {
                    // instruction
                    bytes.append(createInstructionSignature(address));
                } else if (isDataAt(address)) {
                    // data unit (defined or undefined)
                    bytes.append(createDataSignature(address));
                } else if (isCodeUnitAt(address)) {
                    // code unit (codeUnit: data or instruction)
                    bytes.append(createCodeUnitSignature(address));   
                } else {
                    // unknown / not yet supported
                }
            } catch (MemoryAccessException e) {
                // can't do anything
                bytes.append(createAddressPaddedSignature(address));
            }
        }
        
        return bytes.toString();
    }
    
    // =============================================================================================
    // Address Internal Type Peek helpers
    // =============================================================================================
  
    private boolean isInstructionAt(Address address) {
        if (address == null) {
            return false;
        }
        return getListing().getInstructionAt(address) != null;
    }
    
    private boolean isDataAt(Address address) {
        if (address == null) {
            return false;
        }
        return getListing().getDataAt(address) != null;
    }

    private boolean isCodeUnitAt(Address address) {
        if (address == null) {
            return false;
        }
        return getListing().getCodeUnitAt(address) != null;
    }

    private boolean isInFunction(Address address) {
        if (address == null) {
            return false;
        }
        return getListing().isInFunction(address);
    }
    
    // =============================================================================================
    // Formatting / Padding helpers
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
}
