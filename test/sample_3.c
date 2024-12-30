#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Vulnerability 1: Buffer Overflow
void buffer_overflow() {
    char buffer[10];
    strcpy(buffer, "This is a very long string that exceeds buffer size."); // Buffer overflow vulnerability
}

// Vulnerability 2: Format String Vulnerability
void format_string(char *input) {
    printf(input);  // Vulnerable to format string attack if input contains format specifiers
}

// Vulnerability 3: Unvalidated User Input (Command Injection)
void command_injection(char *user_input) {
    char command[256];
    snprintf(command, sizeof(command), "ls %s", user_input); // Potential command injection vulnerability
    system(command);  // Executes the command with user input
}

// Vulnerability 4: Use of Unsafe Functions (strcpy, gets)
void unsafe_string_operations() {
    char buffer[20];
    gets(buffer);  // Vulnerable to buffer overflow
    printf("You entered: %s\n", buffer);
}

// Vulnerability 5: Integer Overflow (Improper Integer Handling)
void integer_overflow() {
    unsigned int x = 4294967295; // Maximum value of unsigned int
    x += 1;  // Overflow occurs here, potentially leading to unexpected behavior
    printf("Overflowed integer value: %u\n", x);
}

// Vulnerability 6: Hardcoded Credentials (Sensitive Data Exposure)
void hardcoded_credentials() {
    char username[] = "admin";
    char password[] = "password123"; // Hardcoded credentials exposed in source code
    printf("Username: %s\nPassword: %s\n", username, password);
}

// Vulnerability 7: Use of Weak Cryptography (Insecure Hashing)
void weak_cryptography() {
    char password[] = "12345";
    unsigned int hash = 0;
    for (int i = 0; i < strlen(password); i++) {
        hash += password[i]; // Simple and weak hash function
    }
    printf("Weak hash: %u\n", hash); // This is an insecure hashing approach
}

// Vulnerability 8: Memory Leak
void memory_leak() {
    char *str = (char *)malloc(100 * sizeof(char));
    strcpy(str, "This memory will not be freed!"); // Memory leak, no free() call
    printf("%s\n", str);
    // Missing free(str); results in memory leak
}

// Vulnerability 9: Uninitialized Memory (Use of Uninitialized Variable)
void uninitialized_memory() {
    int x;
    printf("Uninitialized value: %d\n", x); // Using an uninitialized variable (undefined behavior)
}

// Vulnerability 10: Race Condition (Improper Synchronization)
void race_condition() {
    int counter = 0;

    // Simulate a race condition (e.g., using multiple threads, omitted for simplicity)
    // Without proper synchronization mechanisms like mutex, a race condition could happen
    counter++;
    printf("Counter value: %d\n", counter); // This may not behave as expected in a multithreaded environment
}

int main() {
    // Example function calls that demonstrate the vulnerabilities

    printf("Demonstrating Buffer Overflow:\n");
    buffer_overflow();  // Causes buffer overflow
    
    printf("\nDemonstrating Format String Vulnerability:\n");
    format_string("%s\n");  // Format string attack
    
    printf("\nDemonstrating Command Injection:\n");
    command_injection("; ls /");  // Command injection attack (use semicolon to chain commands)
    
    printf("\nDemonstrating Unsafe String Operations:\n");
    unsafe_string_operations();  // Unsafe string operation
    
    printf("\nDemonstrating Integer Overflow:\n");
    integer_overflow();  // Integer overflow
    
    printf("\nDemonstrating Hardcoded Credentials:\n");
    hardcoded_credentials();  // Hardcoded sensitive data
    
    printf("\nDemonstrating Weak Cryptography:\n");
    weak_cryptography();  // Weak hashing
    
    printf("\nDemonstrating Memory Leak:\n");
    memory_leak();  // Memory leak
    
    printf("\nDemonstrating Uninitialized Memory Usage:\n");
    uninitialized_memory();  // Undefined behavior
    
    printf("\nDemonstrating Race Condition:\n");
    race_condition();  // Race condition
    
    return 0;
}

