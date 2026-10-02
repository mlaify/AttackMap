using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace Carts.Controllers;

[ApiController]
public class CartController : ControllerBase
{
    [HttpPost("/carts/restore")]
    public async Task<IActionResult> Restore() // taint: route
    {
        var cart = await JsonSerializer.DeserializeAsync<Cart>(Request.Body); // taint: sink
        return Ok(cart.Items.Count);
    }
}
