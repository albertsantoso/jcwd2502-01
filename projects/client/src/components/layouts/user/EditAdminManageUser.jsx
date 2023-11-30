import React, { useCallback, useEffect, useState } from "react";

import { axiosInstance } from "../../../lib/axios";

import { useFormik } from "formik";
import toast, { Toaster } from "react-hot-toast";
import Media from "react-media";
import * as yup from "yup";
import {
	Modal,
	ModalContent,
	ModalHeader,
	ModalBody,
	ModalFooter,
	Button,
	useDisclosure,
	Input,
	Select,
	SelectItem,
	Textarea,
	Checkbox,
	Tooltip,
} from "@nextui-org/react";
import axios from "axios";
import { useLocation } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { OnCheckIsLogin } from "../../../redux/features/users";
import { BiEdit } from "react-icons/bi";
import { IoEyeOffOutline, IoEyeOutline } from "react-icons/io5";
const EditAdminManageUser = ({ data, handleRefresh }) => {
	const { isOpen, onOpen, onOpenChange } = useDisclosure();
	const [warehouses, setWarehouses] = useState([]);
	const accessToken = localStorage.getItem("accessToken");
	const dispatch = useDispatch();
	const location = useLocation();
	const [selectedRole, setSelectedRole] = useState(null);
	const [selectedWarehouse, setSelectedWarehouse] = useState();

	const formik = useFormik({
		initialValues: {
			idUser: data?.id,
			username: data?.username,
			email: data?.email,
			warehouse_id: data?.warehouse_id,
			role: data?.role,
		},
		onSubmit: (values) => {
			handleSubmit(values);
			// console.log(values.idUser);
		},
		validationSchema: yup.object().shape({
			username: yup.string().required(),
			email: yup.string().required(),
		}),
	});
	const handleSubmit = async (values) => {
		try {
			const { username, email, password, warehouse_id, role } = values;
			console.log(values);
			const updateDataAdmin = await axiosInstance(accessToken).post(
				"/users/updateAdminData",
				values
			);
			console.log(updateDataAdmin);
			handleRefresh(true);
			// formik.resetForm();
		} catch (error) {
			console.log(error);
		}
	};

	const fetchWarehouses = async () => {
		try {
			const { data } = await axiosInstance().get(`warehouses/all`);
			setWarehouses(data.data);
		} catch (error) {
			console.log(error);
		}
	};

	const renderWarehouseOption = () => {
		return warehouses?.map((item) => {
			return (
				<SelectItem key={item.id} value={item.warehouse_name}>
					{item.warehouse_name}
				</SelectItem>
			);
		});
	};

	const role = [
		{
			id: 1,
			role_name: "admin",
		},
		{
			id: 2,
			role_name: "super",
		},
	];

	const renderRoleOption = () => {
		return role?.map((item) => {
			return (
				<SelectItem key={item.role_name} value={item.id}>
					{item.role_name}
				</SelectItem>
			);
		});
	};

	const handleWarehouse = (item) => {
		setSelectedWarehouse(item);
		formik.setFieldValue("warehouse_id", item);
	};
	const handleRole = (item) => {
		setSelectedRole(item);
		formik.setFieldValue("role", item);
	};
	useEffect(() => {
		fetchWarehouses();
	}, []);
	// useEffect(() => {
	// 	// formik.setFieldValue("recipient_name", username);
	// 	// console.log(formik.values);
	// }, [formik]);

	useEffect(() => {
		formik.setValues({
			idUser: data?.id || "",
			username: data?.username || "",
			email: data?.email || "",
			warehouse_id: data?.warehouse_id || "",
			role: data?.role || "",
		});

		// gender ? setSelectedGender(gender):
	}, [data]);

	return (
		<>
			<Toaster />
			<Media
				queries={{
					medium: "(min-width: 768px)",
				}}
			>
				{(matches) => (
					<>
						<Tooltip content="Edit Admin">
							<Button variant="flat" isIconOnly onPress={onOpen}>
								<BiEdit size={24} />
							</Button>
						</Tooltip>

						<Modal
							isOpen={isOpen}
							onOpenChange={onOpenChange}
							placement={matches.medium ? "center" : "bottom"}
							scrollBehavior="inside"
							// onOpenChange={()=>{onClose();}}
							size={matches.medium ? "2xl" : "full"}
							backdrop={matches.medium ? "blur" : ""}
						>
							<ModalContent>
								{(onClose) => (
									<>
										<ModalHeader className="flex justify-center">
											<h2 className="text-xl font-bold mb-2 pt-3">
												Edit Admin
											</h2>
										</ModalHeader>
										<ModalBody>
											<form
												className="flex flex-col justify-between gap-4 h-full"
												onSubmit={formik.handleSubmit}
											>
												<div className="form-control">
													<Input
														type="text"
														name="username"
														label="Admin's Name"
														labelPlacement="outside"
														variant="bordered"
														radius="sm"
														size="lg"
														placeholder="John Doe"
														defaultValue={
															formik.values
																.username
																? formik.values
																		.username
																: ""
														}
														onChange={
															formik.handleChange
														}
														isRequired
													/>
												</div>
												<div className="form-control">
													<Input
														type="text"
														name="email"
														label="Email"
														labelPlacement="outside"
														variant="bordered"
														radius="sm"
														size="lg"
														placeholder="Home"
														defaultValue={
															formik.values.email
																? formik.values
																		.email
																: ""
														}
														onChange={
															formik.handleChange
														}
														isRequired
													/>
												</div>
												<div className="form-control">
													<Select
														name="role"
														label="Role"
														labelPlacement="outside"
														variant="bordered"
														radius="sm"
														size="lg"
														onChange={
															formik.handleChange
														}
														placeholder="Select a Role"
														isRequired
														selectedKeys={
															formik.values.role
																? [
																		formik
																			.values
																			.role,
																  ]
																: null
														}
													>
														{renderRoleOption()}
													</Select>
												</div>
												<div className="form-control">
													<Select
														name="warehouse_id"
														label="Warehouse"
														labelPlacement="outside"
														variant="bordered"
														radius="sm"
														size="lg"
														onChange={(e) =>
															handleWarehouse(
																e.target.value
															)
														}
														placeholder="Select a warehouse"
														// isRequired
														selectedKeys={
															formik.values
																.warehouse_id
																? [
																		String(
																			formik
																				.values
																				.warehouse_id
																		),
																  ]
																: null
														}
														value={
															formik.values
																.warehouse_id
														}
													>
														{renderWarehouseOption()}
													</Select>
												</div>
											</form>
										</ModalBody>
										<ModalFooter className="justify-center">
											<Button
												color="primary"
												className="text-center mb-4"
												type="submit"
												onClick={(e) => {
													formik.handleSubmit(e);
													onClose();
												}}
												fullWidth
												// onPress={onClose}
											>
												<span className="font-bold text-black">
													Save New Data Admin
												</span>
											</Button>
											<Button
												color="danger"
												className="text-center mb-4"
												type="reset"
												onClick={(e) => {
													// formik.handleSubmit(e);
													formik.resetForm();
													onClose();
												}}
												fullWidth
												// onPress={onClose}
											>
												<span className="font-bold text-black">
													Cancle
												</span>
											</Button>
										</ModalFooter>
									</>
								)}
							</ModalContent>
						</Modal>
					</>
				)}
			</Media>
		</>
	);
};

export default EditAdminManageUser;
