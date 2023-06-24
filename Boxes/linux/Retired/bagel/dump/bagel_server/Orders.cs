using System.Runtime.CompilerServices;

namespace bagel_server
{
	public class Orders
	{
		private string order_filename;

		private string order_info;

		private File file = new File();

		public object RemoveOrder
		{
			[CompilerGenerated]
			get
			{
				return _003CRemoveOrder_003Ek__BackingField;
			}
			[CompilerGenerated]
			set
			{
				_003CRemoveOrder_003Ek__BackingField = value;
			}
		}

		public string WriteOrder
		{
			get
			{
				return file.WriteFile;
			}
			set
			{
				order_info = value;
				file.WriteFile = order_info;
			}
		}

		public string ReadOrder
		{
			get
			{
				return file.ReadFile;
			}
			set
			{
				order_filename = value;
				order_filename = order_filename.Replace("/", "");
				order_filename = order_filename.Replace("..", "");
				file.ReadFile = order_filename;
			}
		}
	}
}
