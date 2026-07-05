import { fetchOrder } from "../db/orders";

export async function placeOrder(orderId: string) {
  return fetchOrder(orderId);
}
