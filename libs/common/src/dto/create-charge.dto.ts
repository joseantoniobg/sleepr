import { IsDefined, IsNotEmptyObject, IsNumber, ValidateNested } from "class-validator";
import { CardDto } from "./card.dto";
import { Type } from "class-transformer";

export class CreateChargeDto {
  @IsDefined()
  @IsNotEmptyObject()
  @ValidateNested()
  @Type((value) => CardDto)
  card: CardDto;

  @IsNumber()
  amount: number;
}