// A real mixed native/managed executable; the native call must survive IAT rewriting.
#using <System.dll>
#pragma managed(push, off)
__declspec(noinline) int native_value() { return 42; }
#pragma managed(pop)

int main(array<System::String^>^ args) {
    if (args->Length != 1 || native_value() != 42) return 2;
    auto name = "ckpt_" + System::Diagnostics::Process::GetCurrentProcess()->Id + ".txt";
    System::IO::File::WriteAllText(System::IO::Path::Combine(args[0], name), "mixed");
    System::Threading::Thread::Sleep(60000);
    return 0;
}
