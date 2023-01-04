import subprocess

class ShellcodeConverter:
    def __init__(self, asm_filename, shellcode_filename):
        self.asm_filename = asm_filename
        self.shellcode_filename = shellcode_filename
    
    def asm_to_shellcode(self, assembler="nasm", platform="elf64"):
        # compile the assembly code into an object file
        subprocess.run([assembler, "-f", platform, self.asm_filename, "-o", "asm.o"])
        
        # extract the shellcode from the object file
        subprocess.run(["objdump", "-d", "asm.o", "--section=.text", "-M", "intel", "-j", ".text", "--set-start", "0x0", "-w", "-l", "-z", "--prefix-addresses", "--show-raw-insn", ">", self.shellcode_filename])
        
        # clean up
        subprocess.run(["rm", "asm.o"])
    
    def shellcode_to_asm(self, disassembler="ndisasm", platform="elf64"):
        # disassemble the shellcode into an assembly file
        subprocess.run([disassembler, "-b", "64", "-", ">" , self.asm_filename], input=open(self.shellcode_filename, "rb").read())
    
    def check_asm(self, assembler="nasm"):
        # check the assembly file for errors
        result = subprocess.run([assembler, "-f", "elf64", "-w+all", "-o", "asm.o", self.asm_filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # print any errors or warnings
        if result.stderr:
            print(result.stderr.decode())
    
    def lengthen_shellcode(self, byte, length):
        # read the shellcode file into a bytes object
        with open(self.shellcode_filename, "rb") as f:
            shellcode = f.read()
        
        # repeat the byte until the desired length is reached
        shellcode += bytes([byte] * (length - len(shellcode)))
        
        # write the lengthened shellcode to the output file
        with open(self.shellcode_filename, "wb") as f:
            f.write(shellcode)
			
	def detect(self, disassembler="ndisasm"):
        # disassemble the shellcode and extract the first instruction
        output = subprocess.run([disassembler, "-b", "64", "-e", "0x0", "-", self.shellcode_filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
        lines = [line for line in output.split("\n") if line]
        instruction = lines[0].split("\t")[1].strip()
        
        # check the first byte of the instruction to determine the architecture
        if instruction.startswith("0f"):
            # two-byte instruction, likely x86-64
            return "x86-64"
        elif instruction.startswith("b8"):
            # mov instruction, likely x86-32
            return "x86-32"
        else:
            # unknown instruction, unable to determine architecture
            return "unknown"
		
	def explain(self, disassembler="ndisasm", platform="elf64"):
        output = subprocess.run([disassembler, "-b", "64", "-e", "0x0", "-", self.asm_filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
        
        lines = [line for line in output.split("\n") if line]
        
        for line in lines:
            address, instruction, explanation = line.split("\t")
            print(f"0x{address}: {instruction.strip()}\n   {explanation.strip()}\n")


		
# example usage
# converter = ShellcodeConverter("asm.asm", "shellcode.bin")
# converter.lengthen_shellcode(0x90, 1000) - lengthens the shellcode to 1000 bytes by repeating the NOP instruction (0x90)

