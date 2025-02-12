using System;
using System.Web;
using System.Collections.Generic;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Threading;

namespace UploadWebForm
{
    /// <summary>
    /// upload1 ??????¨¨|?¨¨¡¥¡ä???
    /// </summary>
    public class upload1 : IHttpHandler
    {

        public void ProcessRequest(HttpContext context2)
        {
            //?????¡ã??????WebSocket¨¨¡¥¡¤?¡À?
            HttpContext.Current.AcceptWebSocketRequest(async (context) =>
            {
                WebSocket socket = context.WebSocket;//Socket
                while (true)
                {
                    ArraySegment<byte> buffer = new ArraySegment<byte>(new byte[1024]);
                    CancellationToken token;
                    WebSocketReceiveResult result = await socket.ReceiveAsync(buffer, token);
                    if (socket.State == WebSocketState.Open)
                    {
                        string userMessage = Encoding.UTF8.GetString(buffer.Array, 0, result.Count);
                        userMessage = "You sent: " + userMessage + " at " +
                                DateTime.Now.ToLongTimeString();
                        buffer = new ArraySegment<byte>(Encoding.UTF8.GetBytes(userMessage));
                        await socket.SendAsync(buffer, WebSocketMessageType.Text, true, CancellationToken.None);
                    }
                    else { break; }
                }
            });
        }

        public bool IsReusable
        {
            get
            {
                return false;
            }
        }
    }
}