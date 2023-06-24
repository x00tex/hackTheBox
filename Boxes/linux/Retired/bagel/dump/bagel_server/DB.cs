using System;
using Microsoft.Data.SqlClient;

namespace bagel_server
{
	public class DB
	{
		[Obsolete("The production team has to decide where the database server will be hosted. This method is not fully implemented.")]
		public void DB_connection()
		{
			//IL_0008: Unknown result type (might be due to invalid IL or missing references)
			//IL_000e: Expected O, but got Unknown
			string text = "Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K";
			SqlConnection val = new SqlConnection(text);
			string text2 = "INSERT INTO orders (Name,Address,Count,Type) VALUES ('Eliot','Street',4,'Baggel')";
		}
	}
}
