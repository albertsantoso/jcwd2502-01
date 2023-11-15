import React, { useState } from "react";
import {
	Button,
	Input,
	Modal,
	ModalBody,
	ModalContent,
	ModalFooter,
	ModalHeader,
	Select,
	Textarea,
	useDisclosure,
} from "@nextui-org/react";
import Media from "react-media";
import { axiosInstance } from "../../../lib/axios";

const AdminCreateNewCategoryModal = () => {
	const { isOpen, onOpen, onOpenChange } = useDisclosure();
	const [categoryType, setCategoryType] = useState("");
	const [isLoading, setIsLoading] = useState(false);
	const onSubmit = async (categoryType) => {
		try {
			setIsLoading(true);

			if (!categoryType) {
				alert("Please fill in all form fields");
				setIsLoading(false);
				return; // Stop further execution
			}

			// const accessToken = localStorage.getItem("accessToken");

			const addCategory = await axiosInstance().post(`categories`, {
				category_type: categoryType,
			});

			if (addCategory.data.isError) {
				alert(addCategory.data.message);
				setIsLoading(false);
				return;
			}

			window.location.reload(false);
			setIsLoading(false);
			return;
		} catch (error) {
			console.log(error);
		}
	};

	return (
		<Media
			queries={{
				medium: "(min-width: 768px)",
			}}
		>
			{(matches) => (
				<>
					<Button color="primary" size="md" onPress={onOpen}>
						<p className="font-medium text-black flex items-center gap-1">
							<span className="text-[20px]">+</span>
							<span>Add New Category</span>
						</p>
					</Button>
					<Modal
						isOpen={isOpen}
						onOpenChange={onOpenChange}
						placement={matches.medium ? "center" : "bottom"}
						scrollBehavior="inside"
						size={matches.medium ? "2xl" : "full"}
					>
						<ModalContent>
							{(onClose) => (
								<>
									<ModalHeader className="flex justify-center">
										<h2 className="text-xl font-bold mb-2">
											Add New Category
										</h2>
									</ModalHeader>
									<ModalBody>
										{/* <form className="flex flex-col gap-4 h-full"> */}
										<div className="form-control">
											<Input
												type="text"
												name="category_type"
												label="Category Name"
												labelPlacement="outside"
												variant="bordered"
												radius="sm"
												size="lg"
												placeholder="Laptop"
												isRequired
												onChange={(e) =>
													setCategoryType(
														e.target.value
													)
												}
											/>
										</div>
										{/* </form> */}
									</ModalBody>
									<ModalFooter className="justify-center">
										<Button
											color="primary"
											className="text-center mb-4"
											isLoading={isLoading}
											fullWidth
											onPress={() =>
												onSubmit(categoryType)
											}
										>
											<span className="font-bold text-black">
												Add new category
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
	);
};

export default AdminCreateNewCategoryModal;
