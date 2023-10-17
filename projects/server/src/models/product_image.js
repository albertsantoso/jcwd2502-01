"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
	class product_image extends Model {
		/**
		 * Helper method for defining associations.
		 * This method is not a part of Sequelize lifecycle.
		 * The `models/index` file will call this method automatically.
		 */
		static associate({ product }) {
			this.belongsTo(product, { foreignKey: "product_id" });
		}
	}
	product_image.init(
		{
			image: DataTypes.STRING,
			createdAt: {
				type: DataTypes.DATE,
				defaultValue: sequelize.literal("CURRENT_TIMESTAMP"),
			},
			updatedAt: {
				type: DataTypes.DATE,
				defaultValue: sequelize.literal("CURRENT_TIMESTAMP"),
			},
		},
		{
			sequelize,
			modelName: "product_image",
			paranoid: true,
		}
	);
	return product_image;
};
