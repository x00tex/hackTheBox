using Newtonsoft.Json;

namespace bagel_server
{
	public class Handler
	{
		public object Serialize(object obj)
		{
			//IL_0003: Unknown result type (might be due to invalid IL or missing references)
			//IL_0008: Unknown result type (might be due to invalid IL or missing references)
			//IL_0015: Expected O, but got Unknown
			JsonSerializerSettings val = new JsonSerializerSettings();
			val.set_TypeNameHandling((TypeNameHandling)4);
			return JsonConvert.SerializeObject(obj, (Formatting)1, val);
		}

		public object Deserialize(string json)
		{
			//IL_0003: Unknown result type (might be due to invalid IL or missing references)
			//IL_0008: Unknown result type (might be due to invalid IL or missing references)
			//IL_0015: Expected O, but got Unknown
			try
			{
				JsonSerializerSettings val = new JsonSerializerSettings();
				val.set_TypeNameHandling((TypeNameHandling)4);
				return JsonConvert.DeserializeObject<Base>(json, val);
			}
			catch
			{
				return "{\"Message\":\"unknown\"}";
			}
		}
	}
}
