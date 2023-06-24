using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using WatsonWebsocket;

namespace bagel_server
{
	public class Bagel
	{
		private static string _ServerIp = "*";

		private static int _ServerPort = 5000;

		private static bool _Ssl = false;

		private static WatsonWsServer _Server = null;

		private static void Main(string[] args)
		{
			InitializeServer();
			StartServer();
			while (true)
			{
				Thread.Sleep(1000);
			}
		}

		private static void InitializeServer()
		{
			//IL_0010: Unknown result type (might be due to invalid IL or missing references)
			//IL_001a: Expected O, but got Unknown
			_Server = new WatsonWsServer(_ServerIp, _ServerPort, _Ssl);
			_Server.set_AcceptInvalidCertificates(true);
			_Server.add_MessageReceived((EventHandler<MessageReceivedEventArgs>)MessageReceived);
		}

		[AsyncStateMachine(typeof(_003CStartServer_003Ed__6))]
		[DebuggerStepThrough]
		private static void StartServer()
		{
			//IL_0007: Unknown result type (might be due to invalid IL or missing references)
			//IL_000c: Unknown result type (might be due to invalid IL or missing references)
			_003CStartServer_003Ed__6 _003CStartServer_003Ed__ = new _003CStartServer_003Ed__6();
			_003CStartServer_003Ed__._003C_003Et__builder = AsyncVoidMethodBuilder.Create();
			_003CStartServer_003Ed__._003C_003E1__state = -1;
			((AsyncVoidMethodBuilder)(ref _003CStartServer_003Ed__._003C_003Et__builder)).Start<_003CStartServer_003Ed__6>(ref _003CStartServer_003Ed__);
		}

		private static void MessageReceived(object sender, MessageReceivedEventArgs args)
		{
			//IL_0008: Unknown result type (might be due to invalid IL or missing references)
			//IL_000e: Unknown result type (might be due to invalid IL or missing references)
			//IL_001b: Unknown result type (might be due to invalid IL or missing references)
			//IL_0020: Unknown result type (might be due to invalid IL or missing references)
			//IL_003b: Unknown result type (might be due to invalid IL or missing references)
			//IL_0040: Unknown result type (might be due to invalid IL or missing references)
			//IL_004b: Unknown result type (might be due to invalid IL or missing references)
			//IL_0050: Unknown result type (might be due to invalid IL or missing references)
			//IL_0088: Unknown result type (might be due to invalid IL or missing references)
			//IL_008e: Unknown result type (might be due to invalid IL or missing references)
			string json = "";
			if (args.get_Data() != ArraySegment<byte>.op_Implicit((byte[])null) && args.get_Data().get_Count() > 0)
			{
				json = Encoding.get_UTF8().GetString(args.get_Data().get_Array(), 0, args.get_Data().get_Count());
			}
			Handler handler = new Handler();
			object obj = handler.Deserialize(json);
			object obj2 = handler.Serialize(obj);
			_Server.SendAsync(args.get_IpPort(), obj2.ToString(), default(CancellationToken));
		}
	}
}
