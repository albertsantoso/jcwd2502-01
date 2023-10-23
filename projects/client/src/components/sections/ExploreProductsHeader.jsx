import React from "react";
import { Button, Select, SelectItem } from "@nextui-org/react";
import { useDispatch, useSelector } from "react-redux";
import { onClear, onSort } from "../../redux/features/products";
import { useNavigate } from "react-router-dom";

const ExploreProductsHeader = () => {
	const dispatch = useDispatch();
	const navigate = useNavigate();
	const search = useSelector((state) => state.products.search);
	const clear = async () => {
		await dispatch(onClear());
		navigate(`/explore${search && `?search=${search}`}`);
		window.location.reload(false);
	};
	return (
		<>
			<div class="header-position sticky top-[54px] md:top-[70px] z-10 bg-background w-full">
				<header class="wall-header flex items-center min-h-[52px] my-container">
					<div class="wall-header__content flex items-center p-0 w-full justify-between">
						<h1
							class="wall-header__title css-69xvwy m-0 pt-6 pb-4 px-0"
							id=""
						>
							{search ? (
								<>
									<span class="title_prefix absolute top-[-6px]">
										Search results for
										<br />
									</span>
								</>
							) : (
								<>
									<span className="font-bold text-title-lg">
										Explore
									</span>
								</>
							)}
							<span className="font-medium text-title-lg">
								{search}
							</span>
						</h1>
						<nav class="wall-header__nav mt-2 hidden md:flex md:gap-4 md:py-4">
							<div className="sort-by flex items-center">
								<div className="w-full mr-2 font-medium">
									Sort by:
								</div>
								<Select
									labelPlacement={"outside-left"}
									size="md"
									variant="bordered"
									className="min-w-[178px]"
									placeholder="Options"
								>
									<SelectItem
										key={"az"}
										value={"az"}
										onClick={() =>
											dispatch(
												onSort("product_name", "asc")
											)
										}
									>
										A-Z
									</SelectItem>
									<SelectItem
										key={"za"}
										value={"za"}
										onClick={() =>
											dispatch(
												onSort("product_name", "desc")
											)
										}
									>
										Z-A
									</SelectItem>
									<SelectItem
										key={"high"}
										value={"high"}
										onClick={() =>
											dispatch(
												onSort("product_price", "desc")
											)
										}
									>
										Highest price
									</SelectItem>
									<SelectItem
										key={"low"}
										value={"low"}
										onClick={() =>
											dispatch(
												onSort("product_price", "asc")
											)
										}
									>
										Lowest price
									</SelectItem>
								</Select>
							</div>
							<Button
								variant="bordered"
								className="border-neutral-200 dark:border-neutral-700"
								onClick={() => clear()}
							>{`Clear Filter(s)`}</Button>
						</nav>
					</div>
				</header>
			</div>
		</>
	);
};

export default ExploreProductsHeader;
