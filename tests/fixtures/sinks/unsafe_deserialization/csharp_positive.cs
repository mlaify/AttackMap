using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

namespace Carts.Controllers;

[ApiController]
public class CartController : ControllerBase
{
    [HttpPost("/carts/restore")]
    public IActionResult Restore() // taint: route
    {
        var formatter = new BinaryFormatter(); // taint: sink
        var cart = (Cart)formatter.Deserialize(Request.Body);
        return Ok(cart.Items.Count);
    }
}
