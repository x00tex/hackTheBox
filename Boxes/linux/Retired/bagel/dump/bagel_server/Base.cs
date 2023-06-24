using System;

namespace bagel_server
{
	public class Base : Orders
	{
		private int userid = 0;

		private string session = "Unauthorized";

		public int UserId
		{
			get
			{
				return userid;
			}
			set
			{
				userid = value;
			}
		}

		public string Session
		{
			get
			{
				return session;
			}
			set
			{
				session = value;
			}
		}

		public string Time => System.DateTime.get_Now().ToString("h:mm:ss");
	}
}
