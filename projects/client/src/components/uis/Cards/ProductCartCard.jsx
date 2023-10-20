import React from "react";

import { Button, Checkbox, Input, cn } from "@nextui-org/react";

import {
	IoAddCircleOutline,
	IoRemoveCircleOutline,
	IoTrashOutline,
} from "react-icons/io5";

import { useDispatch } from "react-redux";
import { changeQuantity, deleteOrder } from "../../../redux/features/carts";

const ProductCartCard = ({ dataProduct }) => {
	const { id, quantity, product } = dataProduct;

	const productPrice = product.product_price.toLocaleString("id-ID", {
		style: "currency",
		currency: "IDR",
		minimumFractionDigits: 0,
		maximumFractionDigits: 0,
	});

	const dispatch = useDispatch();

	return (
		<>
			<div className="product-cart-card py-4">
				<div className="container flex">
					<div className="mt-6">
						<Checkbox
							classNames={{
								base: cn("max-w-full w-full"),
								label: "w-full",
							}}
							value={product.product_name}
						></Checkbox>
					</div>
					<div className="product-cart-card-wrapper w-full flex gap-2 justify-between ml-2">
						<div className="product-card-img-wrapper">
							<img
								src={`http://localhost:8000/static/${product.product_images[0].image.substring(
									7
								)}`}
								alt=""
								className="product-image w-20 md:w-28 rounded-t-[20px] object-contain"
							/>
						</div>
						<div className="product-cart-info w-full">
							<div className="product-detail ml-1">
								<p className="product-title md:font-medium text-body-md md:text-body-lg line-clamp-1">
									{product.product_name}
								</p>
								<div className="flex gap-1 md:gap-2">
									<p className="text-[10px] md:text-label-lg ">
										{product.brand.brand_name} •{" "}
										{product.category.category_type}
									</p>
								</div>
								<p className="price text-body-md md:text-price-sm font-bold">
									{productPrice}
								</p>
							</div>
						</div>
					</div>
				</div>
				<div>
					<div className="product-cart-actions">
						<div className="bottom-right flex items-center justify-end md:justify-end gap-8 mt-2">
							<Button
								isIconOnly
								variant="light"
								size="sm"
								radius="full"
								onClick={() => dispatch(deleteOrder(1, id))}
							>
								<IoTrashOutline size={24} color="#f00" />
							</Button>
							<div className="quantity-controller flex items-center w-[120px]">
								<Button
									onClick={() =>
										dispatch(
											changeQuantity(1, id, "subtract")
										)
									}
									isIconOnly
									color="primary"
									size="sm"
									variant="light"
									radius="full"
								>
									<IoRemoveCircleOutline
										size={26}
										color="#24ef00"
									/>
								</Button>
								<Input
									type="number"
									size="sm"
									value={quantity}
									min={1}
									max={999999}
								/>
								<Button
									onClick={() => {
										dispatch(changeQuantity(1, id, "add"));
									}}
									isIconOnly
									color="primary"
									size="sm"
									variant="light"
									radius="full"
								>
									<IoAddCircleOutline
										size={26}
										color="#24ef00"
									/>
								</Button>
							</div>
						</div>
					</div>
				</div>
			</div>
		</>
	);
};

export default ProductCartCard;
