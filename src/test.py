from pathlib import Path
from vm import VirtualMachine

def run_tests():
    vm = VirtualMachine()
    tests = [
        ["Data Movement", "mov_test.bin"],
        ["Arithmetic", "arith_test.bin"],
        ["Branching", "branch_test.bin"],
        ["Subroutines", "sub_test.bin"],
        ["I/O Operations", "io_test.bin"]
    ]

    # Configuration
    BASE_DIR = Path(__file__).parent.resolve()
    PROGRAMS_DIR = BASE_DIR / "tests"
    DEBUG_MODE = True
    BREAKPOINTS = [0x000A]
    
    # Construct program path
    for i in range(len(tests)):
        program_path = PROGRAMS_DIR / tests[i][1]
        program_path = program_path.resolve()
        tests[i][1] = program_path
    
    for name, filename in tests:
        print(f"\n{'='*40}")
        print(f"Running {name} Test")
        print(f"{'='*40}")
        vm.reset()
        vm.run(filename, debug=True)
        print(f"{'='*40}")
        print(f"Test completed in {vm.cycles} cycles")
        print(f"Final State: A={hex(vm.reg['A'])}, B={hex(vm.reg['B'])}, C={hex(vm.reg['C'])}, D={hex(vm.reg['D'])}")
        print(f"Flags: {vm.reg['FLAGS']:04b} (NZCO)")

if __name__ == "__main__":
    run_tests()
