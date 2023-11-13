import { configureStore } from "@reduxjs/toolkit";
import productsSlice from "../features/products";
import usersSlice from "../features/users";
import cartsSlice from "../features/carts";
import ordersSlice from "../features/orders";

export const store = configureStore({
	reducer: {
		products: productsSlice,
		user: usersSlice,
		carts: cartsSlice,
		orders: ordersSlice,
	},
});
