import React, { useCallback, useEffect, useState } from "react";
import OrderCard from "../../components/uis/Cards/OrderCard";
import { Pagination, Select, SelectItem } from "@nextui-org/react";
import { axiosInstance } from "../../lib/axios";
import { orderStatuses } from "../../data/constant";
import { useLocation } from "react-router-dom";
import NotFound from "../../assets/illustrations/NotFoundillustration.png";

const OrderListPage = () => {
	const token = localStorage.getItem("accessToken");
	const location = useLocation();

	const queryParams = new URLSearchParams(location.search);
	const currentPage = +queryParams.get("page") || 1;
	const currentStatus = +queryParams.get("status") || "";

	const [orders, setOrders] = useState([]);
	const [totalPages, setTotalPages] = useState(1);
	const [isPaginationVisible, setIsPaginationVisible] = useState(false);

	const fetchUserOrderList = async (page, status = "") => {
		try {
			const { data } = await axiosInstance(token).get(
				`orders?page=${page}&status=${status}`
			);

			setOrders(data.data.orderList);
			setTotalPages(data.data.pagination.totalPages);
		} catch (error) {
			console.log(error);
		}
	};

	const handlePageChange = (newPage) => {
		fetchUserOrderList(newPage);
		updateUrl(newPage);
		window.scrollTo({ top: 0 });
	};

	const handleStatusChange = (newStatus) => {
		fetchUserOrderList(currentPage, newStatus);
		updateUrl(1, newStatus);
	};

	const updateUrl = (page, status) => {
		const params = new URLSearchParams();
		params.set("page", page);
		if (status) {
			params.set("status", status);
		}
		window.history.replaceState(
			{},
			"",
			`${window.location.pathname}?${params.toString()}`
		);
	};

	useEffect(() => {
		fetchUserOrderList(currentPage, currentStatus);

		window.scrollTo({ top: 0 });

		const timeoutId = setTimeout(() => {
			setIsPaginationVisible(true);
		}, 200);

		return () => clearTimeout(timeoutId);
	}, [currentPage]);

	const renderPagination = useCallback(() => {
		if (isPaginationVisible && totalPages) {
			return (
				<Pagination
					color="secondary"
					showControls
					total={totalPages || 1}
					page={currentPage || 1}
					onChange={handlePageChange}
				/>
			);
		}
		return null;
	}, [currentPage, currentStatus]);

	const renderOrderList = () => {
		if (orders && orders.length > 0) {
			return orders.map((order) => (
				<OrderCard key={order.id} orderData={order} />
			));
		} else {
			return (
				<div className="md:flex md:items-center md:justify-center py-20 md:py-40">
					<img
						src={NotFound}
						className="w-40 md:w-52 mx-auto md:mx-0 mb-6 md:mb-0"
						alt="Not Found"
					/>
					<h4 className="font-bold md:text-title-lg md:w-1/2 text-center">
						Your transaction history is currently empty. <br /> It's
						time to add some activity to it! 🛒
					</h4>
				</div>
			);
		}
	};

	return (
		<main className="my-container min-h-screen py-4">
			<div className="page-heading mb-4">
				<h3 className="font-bold text-lg md:text-headline-sm">
					Transaction History
				</h3>
			</div>
			<section className="orders">
				<div className="grid grid-cols-1 mb-4">
					<Select
						items={orderStatuses}
						labelPlacement="outside-left"
						placeholder="Order Status"
						variant="bordered"
						size="md"
						className="md:col-span-2"
						onChange={(e) => handleStatusChange(e.target.value)}
						defaultSelectedKeys={
							currentStatus && [String(currentStatus)]
						}
					>
						{(status) => (
							<SelectItem key={status.value}>
								{status.label}
							</SelectItem>
						)}
					</Select>
				</div>
				<div className="order-list-wrapper flex flex-col gap-4">
					{renderOrderList()}
				</div>
				<div className="pagination flex justify-center items-center py-8">
					{renderPagination()}
				</div>
			</section>
		</main>
	);
};

export default OrderListPage;
