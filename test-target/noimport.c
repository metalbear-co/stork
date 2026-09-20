/* No-import native PE-entry fixture.
 *
 * This image imports nothing. The loader maps only what the rewritten import
 * table names: the payload DLL. The entry point spins in place because it can
 * call no imported API. The parent terminates the process when the test ends.
 */
void stork_entry(void) {
    volatile unsigned long counter = 0;
    for (;;) {
        counter += 1;
    }
}
