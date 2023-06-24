using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace bagel_server
{
	public class File
	{
		private string file_content;

		private string IsSuccess = null;

		private string directory = "/opt/bagel/orders/";

		private string filename = "orders.txt";

		public string ReadFile
		{
			get
			{
				return file_content;
			}
			set
			{
				filename = value;
				ReadContent(directory + filename);
			}
		}

		public string WriteFile
		{
			get
			{
				return IsSuccess;
			}
			set
			{
				WriteContent(directory + filename, value);
			}
		}

		public void ReadContent(string path)
		{
			try
			{
				System.Collections.Generic.IEnumerable<string> enumerable = File.ReadLines(path, Encoding.get_UTF8());
				file_content += string.Join("\n", enumerable);
			}
			catch (System.Exception)
			{
				file_content = "Order not found!";
			}
		}

		public void WriteContent(string filename, string line)
		{
			try
			{
				File.WriteAllText(filename, line);
				IsSuccess = "Operation successed";
			}
			catch (System.Exception)
			{
				IsSuccess = "Operation failed";
			}
		}
	}
}
